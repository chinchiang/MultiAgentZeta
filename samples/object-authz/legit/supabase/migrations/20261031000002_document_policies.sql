-- LEGITIMATE BEHAVIOUR: the patched policies plus one sharing exception allowed by the
-- sample's requirements: members of the same tenant may read (only read) a document
-- whose owner marked it shared. Tests must not report this access as a finding.

create policy "owners read documents" on public.documents
  for select to authenticated
  using (owner_id = auth.uid());

create policy "tenant members read shared documents" on public.documents
  for select to authenticated
  using (shared
         and tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

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
