-- Fase 37: enlace propio y gestión de clientes de la administración general.
-- Ejecutar después de Fase 36. La instalación no crea clientes ni cambia accesos existentes.

begin;

alter table public.simfin_profiles
  add column if not exists full_name text not null default '';

alter table public.simfin_profiles drop constraint if exists simfin_profiles_access_source_check;
alter table public.simfin_profiles add constraint simfin_profiles_access_source_check
  check (access_source is null or access_source in ('manual','hotmart','admin','seller','admin_direct'));

create table if not exists public.simfin_admin_direct_links (
  owner_id uuid primary key references public.simfin_profiles(id) on delete cascade,
  code text not null unique default replace(gen_random_uuid()::text,'-',''),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.simfin_admin_direct_clients (
  student_id uuid primary key references public.simfin_profiles(id) on delete cascade,
  owner_id uuid not null references public.simfin_profiles(id) on delete cascade,
  contact_consent boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists simfin_admin_direct_clients_owner_idx
  on public.simfin_admin_direct_clients(owner_id,created_at desc);

alter table public.simfin_admin_direct_links enable row level security;
alter table public.simfin_admin_direct_clients enable row level security;
revoke all on public.simfin_admin_direct_links,public.simfin_admin_direct_clients from anon,authenticated,public;

create or replace function public.simfin_get_admin_direct_link()
returns table(code text,is_active boolean)
language plpgsql security definer set search_path=public as $$
begin
  if not public.simfin_is_super_admin() then raise exception 'Solo la administración general puede consultar su enlace propio.'; end if;
  insert into public.simfin_admin_direct_links(owner_id)
  values(auth.uid()) on conflict(owner_id) do nothing;
  return query select l.code,l.is_active from public.simfin_admin_direct_links l where l.owner_id=auth.uid();
end;
$$;

create or replace function public.simfin_set_admin_direct_link_active(p_active boolean)
returns void language plpgsql security definer set search_path=public as $$
begin
  if not public.simfin_is_super_admin() then raise exception 'Solo la administración general puede gestionar su enlace propio.'; end if;
  update public.simfin_admin_direct_links set is_active=p_active,updated_at=now() where owner_id=auth.uid();
  if not found then raise exception 'No se encontró el enlace propio. Recarga el panel e inténtalo otra vez.'; end if;
end;
$$;

create or replace function public.simfin_rotate_admin_direct_link()
returns text language plpgsql security definer set search_path=public as $$
declare new_code text:=replace(gen_random_uuid()::text,'-','');
begin
  if not public.simfin_is_super_admin() then raise exception 'Solo la administración general puede renovar su enlace propio.'; end if;
  insert into public.simfin_admin_direct_links(owner_id,code,is_active,updated_at)
  values(auth.uid(),new_code,true,now())
  on conflict(owner_id) do update set code=excluded.code,is_active=true,updated_at=now();
  return new_code;
end;
$$;

create or replace function public.simfin_resolve_admin_direct_code(p_code text)
returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.simfin_admin_direct_links l where l.code=trim(coalesce(p_code,'')) and l.is_active);
$$;

create or replace function public.simfin_list_admin_direct_clients()
returns table(student_id uuid,full_name text,email text,phone text,registered_at timestamptz,access_status text,contact_consent boolean)
language plpgsql stable security definer set search_path=public as $$
begin
  if not public.simfin_is_super_admin() then raise exception 'Solo la administración general puede consultar sus clientes propios.'; end if;
  return query
    select p.id,p.full_name,p.email,p.phone,p.registered_at,p.access_status,d.contact_consent
    from public.simfin_admin_direct_clients d
    join public.simfin_profiles p on p.id=d.student_id
    where d.owner_id=auth.uid()
    order by d.created_at desc;
end;
$$;

create or replace function public.simfin_set_admin_direct_client_status(p_student_id uuid,p_status text)
returns void language plpgsql security definer set search_path=public as $$
begin
  if not public.simfin_is_super_admin() then raise exception 'Solo la administración general puede gestionar sus clientes propios.'; end if;
  if p_status not in ('active','blocked') then raise exception 'Estado de acceso no permitido.'; end if;
  update public.simfin_profiles p set access_status=p_status
    where p.id=p_student_id and p.role='user'
      and exists(select 1 from public.simfin_admin_direct_clients d where d.student_id=p.id and d.owner_id=auth.uid());
  if not found then raise exception 'No se encontró ese cliente propio.'; end if;
end;
$$;

-- El RPC público solo confirma si el código está activo; nunca revela al administrador.
revoke all on function public.simfin_get_admin_direct_link() from public,anon;
revoke all on function public.simfin_set_admin_direct_link_active(boolean) from public,anon;
revoke all on function public.simfin_rotate_admin_direct_link() from public,anon;
revoke all on function public.simfin_resolve_admin_direct_code(text) from public;
revoke all on function public.simfin_list_admin_direct_clients() from public,anon;
revoke all on function public.simfin_set_admin_direct_client_status(uuid,text) from public,anon;
grant execute on function public.simfin_get_admin_direct_link() to authenticated;
grant execute on function public.simfin_set_admin_direct_link_active(boolean) to authenticated;
grant execute on function public.simfin_rotate_admin_direct_link() to authenticated;
grant execute on function public.simfin_resolve_admin_direct_code(text) to anon,authenticated;
grant execute on function public.simfin_list_admin_direct_clients() to authenticated;
grant execute on function public.simfin_set_admin_direct_client_status(uuid,text) to authenticated;

-- Extiende el trigger de registro instalado en Fase 35, conservando Hotmart,
-- centros, docentes y vendedores como flujos independientes.
create or replace function public.simfin_create_user_records()
returns trigger language plpgsql security definer set search_path=public as $$
declare
  normalized_email text:=lower(coalesce(new.email,'')); invited_center uuid; invite_status text;
  assigned_center uuid; center_state text; assigned_role text:='user'; assigned_source text;
  seller_email text; seller_name text; seller_phone text; seller_code text:=new.raw_user_meta_data->>'seller_code';
  center_code text:=new.raw_user_meta_data->>'center_code';
  admin_direct_code text:=new.raw_user_meta_data->>'admin_direct_code'; admin_direct_owner uuid;
  contact_phone text:=left(trim(coalesce(new.raw_user_meta_data->>'contact_phone','')),30);
  contact_name text:=left(trim(coalesce(new.raw_user_meta_data->>'full_name','')),120);
  contact_consent boolean:=coalesce(new.raw_user_meta_data->>'seller_contact_consent','false')='true';
  admin_direct_consent boolean:=coalesce(new.raw_user_meta_data->>'admin_direct_contact_consent','false')='true';
  admin_name text; teacher_name text; hotmart_transaction text;
begin
  if normalized_email='webyappmovil@gmail.com' then
    assigned_role:='super_admin'; assigned_source:='admin';
  else
    select i.center_id,i.status into invited_center,invite_status from public.simfin_center_admin_invites i where i.email=normalized_email;
    if found then
      if invite_status<>'authorized' then raise exception 'Este correo de administrador no está autorizado para registrarse.'; end if;
      select c.status into center_state from public.simfin_centers c where c.id=invited_center;
      if center_state is distinct from 'active' then raise exception 'El centro está desactivado.'; end if;
      assigned_center:=invited_center; assigned_role:='center_admin'; assigned_source:='admin';
      update public.simfin_center_admin_invites set status='active',updated_at=now() where email=normalized_email;
    else
      select i.center_id,i.status,i.full_name into invited_center,invite_status,teacher_name from public.simfin_teacher_invites i where i.email=normalized_email;
      if found then
        if invite_status<>'authorized' then raise exception 'Este correo docente no está autorizado para registrarse.'; end if;
        select c.status into center_state from public.simfin_centers c where c.id=invited_center;
        if center_state is distinct from 'active' then raise exception 'El centro está desactivado.'; end if;
        assigned_center:=invited_center; assigned_role:='teacher'; assigned_source:='admin';
        update public.simfin_teacher_invites set status='active',updated_at=now() where email=normalized_email;
      else
        select s.full_name,s.phone,s.status into seller_name,seller_phone,invite_status from public.simfin_sellers s where s.email=normalized_email;
        if found then
          if invite_status<>'authorized' then raise exception 'Este correo de vendedor no está autorizado para registrarse.'; end if;
          assigned_role:='seller'; assigned_source:='admin';
        else
          if admin_direct_code is not null and trim(admin_direct_code)<>'' then
            if coalesce(seller_code,'')<>'' or coalesce(center_code,'')<>'' then raise exception 'Usa solo un enlace de registro a la vez.'; end if;
            select l.owner_id into admin_direct_owner from public.simfin_admin_direct_links l
              where l.code=trim(admin_direct_code) and l.is_active;
            if not found then raise exception 'El enlace directo de administración no es válido o está desactivado.'; end if;
            if length(trim(contact_name))<2 then raise exception 'Escribe tu nombre y apellidos.'; end if;
            if length(regexp_replace(contact_phone,'[^0-9]','','g'))<7 then raise exception 'Escribe un teléfono válido para tu registro.'; end if;
            if not admin_direct_consent then raise exception 'Autoriza a la administración general a consultar tus datos de contacto para completar el registro.'; end if;
            assigned_source:='admin_direct';
          elsif seller_code is not null and trim(seller_code)<>'' then
            select s.email,s.status into seller_email,invite_status from public.simfin_sellers s where s.referral_code=trim(seller_code);
            if not found or invite_status<>'active' then raise exception 'El enlace de vendedor no es válido o está desactivado.'; end if;
            if length(regexp_replace(contact_phone,'[^0-9]','','g'))<7 then raise exception 'Escribe un teléfono válido para tu registro.'; end if;
            assigned_source:='seller';
          elsif center_code is not null and trim(center_code)<>'' then
            select i.center_id,i.status,i.email,i.admin_name,i.admin_phone,c.status into assigned_center,invite_status,seller_email,admin_name,seller_phone,center_state
            from public.simfin_center_admin_invites i join public.simfin_centers c on c.id=i.center_id where i.enrollment_code=center_code;
            if found then
              if invite_status not in ('authorized','active') then raise exception 'El enlace de inscripción fue desactivado.'; end if;
              if center_state<>'active' then raise exception 'El centro está desactivado.'; end if;
            else
              select c.id,c.status into assigned_center,center_state from public.simfin_centers c where c.enrollment_code=center_code;
              if assigned_center is null then raise exception 'El enlace del centro no es válido o está desactivado.'; end if;
              if center_state<>'active' then raise exception 'El centro está desactivado.'; end if;
            end if;
          else
            assigned_source:='hotmart';
            select h.transaction_id into hotmart_transaction from public.simfin_hotmart_orders h
              where h.buyer_email=normalized_email and h.purchase_status='approved' order by h.approved_at desc nulls last limit 1;
          end if;
        end if;
      end if;
    end if;
  end if;
  insert into public.simfin_profiles(id,email,registered_at,access_status,access_source,role,center_id,phone,hotmart_transaction_id,full_name)
  values(new.id,normalized_email,coalesce(new.created_at,now()),
    case when assigned_source='admin_direct' or (assigned_source='hotmart' and hotmart_transaction is null) then 'pending' else 'active' end,
    assigned_source,assigned_role,assigned_center,contact_phone,hotmart_transaction,contact_name)
  on conflict(id) do update set phone=excluded.phone,full_name=excluded.full_name;
  if assigned_role in ('super_admin','center_admin') then
    insert into public.simfin_scenarios(user_id,scenario) values(new.id,'{}'::jsonb) on conflict(user_id) do nothing;
  end if;
  if assigned_role='seller' then
    update public.simfin_sellers set profile_id=new.id,status='active',updated_at=now() where email=normalized_email;
  end if;
  if assigned_role='user' and assigned_source='admin_direct' then
    insert into public.simfin_admin_direct_clients(student_id,owner_id,contact_consent)
      values(new.id,admin_direct_owner,admin_direct_consent) on conflict(student_id) do nothing;
    insert into public.simfin_direct_progress(student_id,scenario) values(new.id,'{}'::jsonb) on conflict(student_id) do nothing;
  elsif assigned_role='user' and seller_email is not null and seller_code is not null then
    insert into public.simfin_direct_clients(student_id,seller_email,contact_consent) values(new.id,seller_email,contact_consent) on conflict(student_id) do nothing;
    insert into public.simfin_direct_progress(student_id,scenario) values(new.id,'{}'::jsonb) on conflict(student_id) do nothing;
  elsif assigned_role='user' and seller_email is not null then
    insert into public.simfin_student_attributions(student_id,admin_email,admin_name,admin_phone)
      values(new.id,seller_email,coalesce(admin_name,''),coalesce(seller_phone,'')) on conflict(student_id) do nothing;
  elsif assigned_role='user' and assigned_center is null then
    insert into public.simfin_direct_progress(student_id,scenario) values(new.id,'{}'::jsonb) on conflict(student_id) do nothing;
  end if;
  return new;
end;
$$;

commit;
