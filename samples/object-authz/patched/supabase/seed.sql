-- Synthetic test data (identical in all versions). Every row carries a unique marker.
-- Test identities have no usable password here: the toolkit sets a random,
-- per-environment password through the provisioning identity at prepare time.

insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
                        raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
                        confirmation_token, recovery_token, email_change_token_new, email_change)
values
  ('00000000-0000-0000-0000-000000000000', 'a0000000-0000-4000-8000-00000000a11c', 'authenticated', 'authenticated',
   'alice@tenant-a.test', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', ''),
  ('00000000-0000-0000-0000-000000000000', 'a0000000-0000-4000-8000-000000000b0b', 'authenticated', 'authenticated',
   'bob@tenant-a.test', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', ''),
  ('00000000-0000-0000-0000-000000000000', 'b0000000-0000-4000-8000-0000000ca201', 'authenticated', 'authenticated',
   'carol@tenant-b.test', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');

insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
select gen_random_uuid(), id, id::text, jsonb_build_object('sub', id::text, 'email', email), 'email', now(), now(), now()
from auth.users
where email like '%.test';

insert into public.tenants (id, name) values
  ('7e000000-0000-4000-8000-00000000000a', 'Tenant A'),
  ('7e000000-0000-4000-8000-00000000000b', 'Tenant B');

insert into public.memberships (tenant_id, user_id, role) values
  ('7e000000-0000-4000-8000-00000000000a', 'a0000000-0000-4000-8000-00000000a11c', 'member'),
  ('7e000000-0000-4000-8000-00000000000a', 'a0000000-0000-4000-8000-000000000b0b', 'member'),
  ('7e000000-0000-4000-8000-00000000000b', 'b0000000-0000-4000-8000-0000000ca201', 'member');

insert into public.documents (id, tenant_id, owner_id, title, body, shared) values
  ('d0000000-0000-4000-8000-0000000000a1', '7e000000-0000-4000-8000-00000000000a',
   'a0000000-0000-4000-8000-00000000a11c', 'MARK-A-ALICE-PRIVATE', 'alice private note', false),
  ('d0000000-0000-4000-8000-0000000000a2', '7e000000-0000-4000-8000-00000000000a',
   'a0000000-0000-4000-8000-00000000a11c', 'MARK-A-ALICE-SHARED', 'alice shared note', true),
  ('d0000000-0000-4000-8000-0000000000b1', '7e000000-0000-4000-8000-00000000000b',
   'b0000000-0000-4000-8000-0000000ca201', 'MARK-B-CAROL-PRIVATE', 'carol private note', false);
