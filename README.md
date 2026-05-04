# Oryga Backend

Supabase backend for Oryga.

## Structure

- `supabase/functions/server`: Deno/Supabase Edge Function code.
- `supabase/migrations`: Database migrations.

## Deploy

Deploy the server function from this repository with the Supabase CLI:

```bash
npx supabase functions deploy server
```

Apply the single consolidated migration with:

```bash
npx supabase db push --include-all
```

If your linked project already has old migration history that no longer exists
locally, run this file directly in the Supabase SQL editor instead:

`supabase/migrations/20260504_001_oryga_full_schema.sql`
