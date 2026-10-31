-- PATCHED: only the owner can read, change or delete a document.

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
