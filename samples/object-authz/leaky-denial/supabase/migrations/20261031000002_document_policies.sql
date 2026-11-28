-- LEAKY DENIAL (a sample WITH a vulnerability): as in the patched version only the owner
-- can read, change or delete a document, and a member of the same tenant who asks for
-- another member's document is refused. But the refusal says too much: its error message
-- carries the title and the body of the document it refuses to show.
-- The response is a proper 403 and nothing changes in the database, so only one of the
-- four checks of a denial case does not hold: the one on disclosure (TK-DYN-001 item 3).

create function public.refuse_with_details(doc public.documents) returns boolean
  language plpgsql stable as $$
begin
  if doc.owner_id <> auth.uid()
     and doc.tenant_id in (select tenant_id from public.memberships where user_id = auth.uid()) then
    raise exception using errcode = '42501',
      message = format('document %s belongs to another member: %s', doc.title, doc.body);
  end if;
  return false;
end $$;

create policy "owners read documents" on public.documents
  for select to authenticated
  using (owner_id = auth.uid() or public.refuse_with_details(documents));

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
