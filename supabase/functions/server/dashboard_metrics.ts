import * as kv from "./kv_store.tsx";

function getTrend(current: number) {
    const randomPercent = Math.floor(Math.random() * 15) + 1;
    const isUp = Math.random() > 0.4;
    return {
        value: randomPercent,
        direction: isUp ? 'up' : 'down'
    };
}

export async function getAdvancedDashboardStats(user: any, date: string) {
    const hospitalId = user.id;
    const today = date || new Date().toISOString().split('T')[0];

    const allAppointments = await kv.getByPrefix("appointment:");
    const allSlots = await kv.getByPrefix("slot:");
    const allProfiles = await kv.getByPrefix("doctor_profile:");

    const hospitalAppointments = allAppointments.filter((apt: any) => apt.hospitalId === hospitalId);
    const hospitalSlots = allSlots.filter((slot: any) => slot.ownerId === hospitalId);
    const hospitalDoctors = allProfiles.filter((doc: any) => doc.hospitalId === hospitalId);

    const todayAppointments = hospitalAppointments.filter((apt: any) => apt.date === today);
    const todaySlots = hospitalSlots.filter((slot: any) => slot.date === today);

    const opdCount = todayAppointments.length;
    const completedAppointments = todayAppointments.filter((apt: any) => apt.status === 'Completed').length;
    const pendingAppointments = todayAppointments.filter((apt: any) => apt.status !== 'Completed' && apt.status !== 'Cancelled').length;
    const activeDocsCount = hospitalDoctors.length;

    const revenueActual = completedAppointments * 500;
    const revenueExpected = opdCount * 500;

    const kpi = {
        opd: {
            value: opdCount,
            trend: getTrend(opdCount)
        },
        activeDoctors: {
            value: activeDocsCount,
            utilization: activeDocsCount > 0 ? Math.round((todayAppointments.length / (todaySlots.length || 1)) * 100) : 0,
            trend: getTrend(activeDocsCount)
        },
        appointments: {
            total: opdCount,
            completed: completedAppointments,
            pending: pendingAppointments,
            trend: getTrend(opdCount)
        },
        revenue: {
            actual: revenueActual,
            expected: revenueExpected,
            trend: getTrend(revenueActual)
        }
    };

    const profile = await kv.get(`hospital_profile:${hospitalId}`) || {};
    const deptConfigs = profile.departments || [];

    const departments: Record<string, any> = {};

    hospitalDoctors.forEach((doc: any) => {
        const deptName = doc.specialty || 'General OPD';
        if (!departments[deptName]) {
            departments[deptName] = {
                id: deptName,
                name: deptName,
                activeDoctors: 0,
                appointments: [],
                slots: []
            };
        }
        departments[deptName].activeDoctors++;
    });

    todayAppointments.forEach((apt: any) => {
        const docId = apt.doctorId || apt.doctor?.id;
        const doc = hospitalDoctors.find((d: any) => d.id === docId || String(d.id) === String(docId));
        const deptName = doc?.specialty || 'General OPD';

        if (!departments[deptName]) {
             departments[deptName] = { id: deptName, name: deptName, activeDoctors: 0, appointments: [], slots: [] };
        }
        departments[deptName].appointments.push(apt);
    });

    const departmentMetrics = Object.values(departments).map((dept: any) => {
        const queueLength = dept.appointments.filter((a: any) => a.status !== 'Completed' && a.status !== 'Cancelled').length;
        const avgWaitTime = dept.activeDoctors > 0 ? Math.round((queueLength * 15) / dept.activeDoctors) : 0;

        let status = 'Normal';
        if (avgWaitTime > 45) status = 'Overloaded';
        else if (avgWaitTime > 20) status = 'Busy';

        const config = deptConfigs.find((d:any) => d.name === dept.name);
        if (config) {
             if (config.load_threshold === 'critical') status = 'Overloaded';
             else if (config.load_threshold === 'high') status = 'Busy';
        }

        return {
            id: dept.id,
            name: dept.name,
            queueLength,
            avgWaitTime,
            activeDoctors: dept.activeDoctors,
            status
        };
    });

    const dailyRunRate = revenueActual;
    const daysInMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).getDate();
    const currentDay = new Date().getDate();
    const currentMonth = new Date().toISOString().slice(0, 7);
    const monthAppointments = hospitalAppointments.filter((apt: any) => apt.date && apt.date.startsWith(currentMonth) && apt.status === 'Completed');

    // BUG FIX: reduce was ignoring `sum` and always adding the hardcoded value 500,
    // discarding actual appointment fees. Now uses apt.fee with 500 as fallback.
    const mtdRevenue = monthAppointments.reduce((sum: number, apt: any) => sum + (apt.fee || 500), 0);
    const projectedRevenue = Math.round((mtdRevenue / Math.max(currentDay, 1)) * daysInMonth);

    const finance = {
        dailyRunRate,
        mtdRevenue,
        projectedRevenue,
        trend: projectedRevenue > (mtdRevenue * 1.1) ? 'up' : 'stable'
    };

    const doctorUtilization = hospitalDoctors.map((doc: any) => {
        const assignedSlots = todaySlots.filter((s: any) => s.doctorId === doc.id);
        const docAppts = todayAppointments.filter((apt: any) => apt.doctorId === doc.id || apt.doctor?.id === doc.id);

        return {
            id: doc.id,
            name: doc.name,
            department: doc.specialty || 'General',
            slotsAssigned: assignedSlots.length,
            slotsUsed: docAppts.length,
            avgConsultTime: 15,
            utilization: assignedSlots.length > 0 ? Math.round((docAppts.length / assignedSlots.length) * 100) : 0
        };
    });

    const alerts = [];

    const overloadedDepts = departmentMetrics.filter(d => d.status === 'Overloaded');
    overloadedDepts.forEach(d => alerts.push({ type: 'critical', message: `${d.name} is Overloaded (${d.avgWaitTime}m wait)` }));

    hospitalDoctors.forEach((doc: any) => {
        const hasSlots = todaySlots.some((s: any) => s.doctorId === doc.id);
        if (!hasSlots) {
             alerts.push({ type: 'warning', message: `Dr. ${doc.name} has no slots assigned today` });
        }
    });

    if (revenueActual < (revenueExpected * 0.5) && opdCount > 5) {
        alerts.push({ type: 'warning', message: 'Revenue below 50% of expected' });
    }

    return {
        date: today,
        kpi,
        departments: departmentMetrics,
        finance,
        doctorUtilization,
        alerts
    };
}
