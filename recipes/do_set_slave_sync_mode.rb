#
# Cookbook Name:: db_postgres
#
# Copyright RightScale, Inc. All rights reserved.
# All access and use subject to the RightScale Terms of Service available at
# http://www.rightscale.com/terms.php and, if applicable, other agreements
# such as a RightScale Master Subscription Agreement.

rightscale_marker

# Run only on master server
# See cookbooks/db/definitions/db_state_assert.rb for the "db_state_assert" definition.
db_state_assert :master

sync_mode = node[:db_postgres][:sync_mode]

log "  Initializing slave(s) to connect to master in #{sync_mode} mode..."
# Sets master-slave replication mode.
# See cookbooks/db_postgres/definitions/db_postgres_set_psqlconf.rb
# for the "db_postgres_set_psqlconf" definition.
db_postgres_set_psqlconf "setup_postgresql_conf" do
  sync_state sync_mode
end

# Reload postgresql to read new updated postgresql.conf
log "  Reload postgresql to read new updated postgresql.conf"
ruby_block "pg_reload_conf" do
  block do
    RightScale::Database::PostgreSQL::Helper.do_query("select pg_reload_conf()")
  end
end
