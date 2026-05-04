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

Apply migrations with:

```bash
npx supabase db push
```
