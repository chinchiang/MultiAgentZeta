-- VULNERABLE: the policies check tenant membership only, not ownership.
-- A same-tenant non-owner can read, change and delete another member's private documents.

create policy "tenant members read documents" on public.documents
  for select to authenticated
  using (tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "tenant members create documents" on public.documents
  for insert to authenticated
  with check (owner_id = auth.uid()
              and tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "tenant members update documents" on public.documents
  for update to authenticated
  using (tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "tenant members delete documents" on public.documents
  for delete to authenticated
  using (tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));
