import * as kv from "./kv_store.tsx";

// Helper to simulate data for the dashboard since we don't have historical data or granular timestamps
function getTrend(current: number) {
    const randomPercent = Math.floor(Math.random() * 15) + 1;
    const isUp = Math.random() > 0.4; // Slightly biased towards growth
    return {
        value: randomPercent,
        direction: isUp ? 'up' : 'down'
    };
}

export async function getAdvancedDashboardStats(user: any, date: string) {
    const hospitalId = user.id;
    const today = date || new Date().toISOString().split('T')[0];

    // 1. Fetch All Data (Simulated Joins)
    const allAppointments = await kv.getByPrefix("appointment:");
    const allSlots = await kv.getByPrefix("slot:");
    const allProfiles = await kv.getByPrefix("doctor_profile:");

    // Filter for Hospital
    const hospitalAppointments = allAppointments.filter((apt: any) => apt.hospitalId === hospitalId);
    const hospitalSlots = allSlots.filter((slot: any) => slot.ownerId === hospitalId); // Assuming hospital owns slots
    const hospitalDoctors = allProfiles.filter((doc: any) => doc.hospitalId === hospitalId);

    // Filter for Today
    const todayAppointments = hospitalAppointments.filter((apt: any) => apt.date === today);
    const todaySlots = hospitalSlots.filter((slot: any) => slot.date === today);

    // --- KPI STRIP CALCULATIONS ---
    const opdCount = todayAppointments.length;
    const completedAppointments = todayAppointments.filter((apt: any) => apt.status === 'Completed').length;
    const pendingAppointments = todayAppointments.filter((apt: any) => apt.status !== 'Completed' && apt.status !== 'Cancelled').length;
    const activeDocsCount = hospitalDoctors.length; // Active roster
    
    // Revenue
    const revenueActual = completedAppointments * 500; // Mock fee if not in apt
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

    // --- DEPARTMENT MONITORING ---
    // Fetch Profile for Department Config to respect overrides
    const profile = await kv.get(`hospital_profile:${hospitalId}`) || {};
    const deptConfigs = profile.departments || []; 

    // Group doctors by specialty -> Department
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

    // Assign appointments to departments (via doctor)
    todayAppointments.forEach((apt: any) => {
        // Find doctor for this apt
        const docId = apt.doctorId || apt.doctor?.id;
        const doc = hospitalDoctors.find((d: any) => d.id === docId || String(d.id) === String(docId));
        const deptName = doc?.specialty || 'General OPD';
        
        if (!departments[deptName]) {
             // Case: Doctor might have been deleted or legacy data
             departments[deptName] = { id: deptName, name: deptName, activeDoctors: 0, appointments: [], slots: [] };
        }
        departments[deptName].appointments.push(apt);
    });

    const departmentMetrics = Object.values(departments).map((dept: any) => {
        const queueLength = dept.appointments.filter((a: any) => a.status !== 'Completed' && a.status !== 'Cancelled').length;
        
        // Mock wait time calculation: 5 mins per person in queue / active docs
        const avgWaitTime = dept.activeDoctors > 0 ? Math.round((queueLength * 15) / dept.activeDoctors) : 0;
        
        let status = 'Normal';
        if (avgWaitTime > 45) status = 'Overloaded';
        else if (avgWaitTime > 20) status = 'Busy';

        // Apply Override from Profile
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

    // --- FINANCIAL PROJECTION ---
    const dailyRunRate = revenueActual; // Simplified for "Today"
    const daysInMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).getDate();
    const currentDay = new Date().getDate();
    // Simple projection: (Revenue so far / days so far) * days in month
    // We don't have historical revenue in KV easily accessible for MTD sum without scanning ALL appointments.
    // We will scan all hospital appointments for THIS MONTH.
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
    const monthAppointments = hospitalAppointments.filter((apt: any) => apt.date && apt.date.startsWith(currentMonth) && apt.status === 'Completed');
    
    const mtdRevenue = monthAppointments.reduce((sum: number, apt: any) => sum + 500, 0);
    const projectedRevenue = Math.round((mtdRevenue / Math.max(currentDay, 1)) * daysInMonth);

    const finance = {
        dailyRunRate,
        mtdRevenue,
        projectedRevenue,
        trend: projectedRevenue > (mtdRevenue * 1.1) ? 'up' : 'stable' // Simple logic
    };

    // --- DOCTOR UTILIZATION ---
    const doctorUtilization = hospitalDoctors.map((doc: any) => {
        const docSlots = todaySlots.filter((s: any) => s.doctorId === doc.id || (!s.doctorId && s.ownerId === hospitalId)); // Simplified assignment
        // Actually, generic slots are "shared". We should only count explicit assignments or bookings.
        // Let's count "Slots Assigned" as slots specifically for them OR total slots / doc count if generic? 
        // Better: Count slots where they are the 'doctorId'.
        const assignedSlots = todaySlots.filter((s: any) => s.doctorId === doc.id);
        const docAppts = todayAppointments.filter((apt: any) => apt.doctorId === doc.id || apt.doctor?.id === doc.id);
        
        return {
            id: doc.id,
            name: doc.name,
            department: doc.specialty || 'General',
            slotsAssigned: assignedSlots.length,
            slotsUsed: docAppts.length,
            avgConsultTime: 15, // Mock constant
            utilization: assignedSlots.length > 0 ? Math.round((docAppts.length / assignedSlots.length) * 100) : 0
        };
    });

    // --- ALERTS ---
    const alerts = [];
    
    // Rule: Overloaded Dept
    const overloadedDepts = departmentMetrics.filter(d => d.status === 'Overloaded');
    overloadedDepts.forEach(d => alerts.push({ type: 'critical', message: `${d.name} is Overloaded (${d.avgWaitTime}m wait)` }));

    // Rule: Doctor available but no slots
    hospitalDoctors.forEach((doc: any) => {
        const hasSlots = todaySlots.some((s: any) => s.doctorId === doc.id);
        if (!hasSlots) {
             alerts.push({ type: 'warning', message: `Dr. ${doc.name} has no slots assigned today` });
        }
    });

    // Rule: Revenue Anomaly (if actual is way below expected)
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