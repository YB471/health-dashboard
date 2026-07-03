-- Per-IP login-attempt throttle for the dashboard edge function.
-- Written/read only by the service-role edge function; RLS on with no policies = deny-all to anon.
-- Applied to project pjuwipjyxzxlmhebzdct on 2026-07-03.
CREATE TABLE IF NOT EXISTS public.auth_throttle (
  ip           text PRIMARY KEY,
  fails        integer NOT NULL DEFAULT 0,
  first_fail   timestamptz,
  locked_until timestamptz,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.auth_throttle ENABLE ROW LEVEL SECURITY;
COMMENT ON TABLE public.auth_throttle IS 'Per-IP dashboard login throttling (service-role only; RLS deny-all to anon).';
