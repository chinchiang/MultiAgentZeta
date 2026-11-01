-- LAX UPDATE POLICY (a sample WITHOUT a vulnerability): reads are owner-only, as in the
-- patched version, but the update policy admits every member of the tenant.
-- Through the data API this is not exploitable: an UPDATE that reads columns (WHERE,
-- RETURNING) must also pass the SELECT policies (PostgreSQL, CREATE POLICY), so a
-- same-tenant non-owner cannot reach the owner's rows. The toolkit must judge by the
-- actual result, not by how wide a policy looks (TK-DYN-002, TK-DYN-004).

create policy "owners read documents" on public.documents
  for select to authenticated
  using (owner_id = auth.uid());

create policy "members create own documents" on public.documents
  for insert to authenticated
  with check (owner_id = auth.uid()
              and tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "tenant members update documents" on public.documents
  for update to authenticated
  using (tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()))
  with check (tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()));

create policy "owners delete documents" on public.documents
  for delete to authenticated
  using (owner_id = auth.uid());
