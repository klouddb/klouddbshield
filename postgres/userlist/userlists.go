package userlist

import (
	"context"
	"database/sql"

	"github.com/klouddb/klouddbshield/model"
)

var runner = []UserlistHelper{
	{
		Title: "List of db users",
		Query: `SELECT r.rolname, r.rolsuper, r.rolinherit,
		r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
		r.rolconnlimit, r.rolvaliduntil,
		ARRAY(SELECT b.rolname
        	FROM pg_catalog.pg_auth_members m
         	JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
          	WHERE m.member = r.oid) as memberof, r.rolreplication
        FROM pg_catalog.pg_roles r
        ORDER BY 1;`,
	},
	{
		Title: "Roles with Superuser attribute",
		Note:  "NOTE - Ensure excessive administrative privileges are revoked",
		Query: `select rolname from pg_roles where rolsuper IS TRUE ;`,
	},
	{
		Title: "Users with CREATEDB",
		Note:  "NOTE - Ensure excessive administrative privileges are revoked",
		Query: `select rolname from pg_roles where rolcreatedb IS TRUE ;`,
	},
	{
		Title: "Users with CREATEROLE",
		Note:  "NOTE - Ensure excessive administrative privileges are revoked",
		Query: `select rolname from pg_roles where rolcreaterole IS TRUE ;`,
	},
	{
		Title: "Users with NOINHERIT",
		Note:  "NOTE - Ensure excessive administrative privileges are revoked",
		Query: `select rolname from pg_roles where rolinherit IS TRUE ;`,
	},
	{
		Title: "Users with BYPASSRLS",
		Note:  "NOTE - Ensure excessive administrative privileges are revoked",
		Query: `SELECT usename FROM pg_catalog.pg_user WHERE usebypassrls IS TRUE;`,
	},
	{
		Title: "Users without connection limits",
		Note:  "NOTE - It is better to apply connection limits to users",
		Query: `select rolname from pg_roles where rolconnlimit=-1 ;`,
	},
	{
		Title: "Password expiry not set (Roles without password expiry)",
		Note:  "NOTE - Please set password expiry as needed",
		Query: `select rolname from pg_roles where rolvaliduntil IS NULL ;`,
	},
	{
		Title: "Roles with default config set",
		Note:  "NOTE - Review below output to see if you have any role level custom config",
		Query: `select rolname, rolconfig from pg_roles where rolname in ('a','b');`,
	},
	{
		Title: "Roles with replication set",
		Query: `select rolname from pg_roles where rolreplication IS TRUE ;`,
	},
}

func Run(ctx context.Context, db *sql.DB) []model.UserlistResult {
	out := []model.UserlistResult{}
	for _, r := range runner {
		out = append(out, *r.Process(db, ctx))
	}

	return out
}
