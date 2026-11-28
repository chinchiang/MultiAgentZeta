-- SIDE EFFECT ON DENIAL (a sample WITH a vulnerability): the policies are those of the
-- patched version, so an update by anyone but the owner changes no row of the owner's.
-- But every update request on the table first runs a statement trigger that rewrites
-- another document, whoever asks, and then answers 403 when the request was refused.
-- The target row is untouched and nothing is disclosed, so only one of the four checks
-- of a denial case does not hold: the one on the response and its side effects
-- (TK-DYN-001 item 4). A 403 is not proof that nothing happened (TK-DYN-002).

create function public.touch_on_any_update() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if pg_trigger_depth() > 1 then
    return null;  -- the trigger's own update below
  end if;
  update public.documents set body = body || ' (touched)' where title = 'MARK-A-ALICE-SHARED-TO-B';
  if not exists (select 1 from public.documents
                 where owner_id = auth.uid() and title = 'MARK-A-ALICE-SHARED-TO-B') then
    -- PostgREST takes the status of the response from this setting; the transaction still commits.
    perform set_config('response.status', '403', true);
  end if;
  return null;
end $$;

create trigger touch_on_any_update before update on public.documents
  for each statement execute function public.touch_on_any_update();

create policy "owners read documents" on public.documents
  for select to authenticated
  using (owner_id = auth.uid());

create policy "members create own documents" on public.documents
  for insert to authenticated
  with check (owner_id = auth.uid()
              and tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "owners update documents" on public.documents
  for update to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

create policy "owners delete documents" on public.documents
  for delete to authenticated
  using (owner_id = auth.uid());
