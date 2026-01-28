# frozen_string_literal: true

require 'open3'
require 'optparse'
require 'tmpdir'

options = {
  base: "kerberos/realms",
  etypes: %w[aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96],
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "usage: #{File::basename $PROGRAM_NAME} [options] <REALM_NAME>"

  opts.on('-b', '--base PATH', 'Path at which realm database data is located.') do |path|
    raise "base path does not exist: #{path}" unless File::directory?(path)

    options[:base] = path
  end

  opts.on('-e', '--encryption-types TYPES', 'Comma-separated list of default encryptions for the realm.') do |etypes|
    options[:etypes] = etypes.split(',')
  end

  opts.on('-v', '--verbose', 'Provide verbose output.') do
    options[:verbose] = true
  end
end.parse!

raise 'missing required parameter: REALM_NAME' if ARGV.length != 1

realm = ARGV[0]

verbose = options[:verbose]

realm_data = "#{options[:base]}/#{realm}"

raise "Realm data directory #{realm_data} does not exist!" unless File::directory?(realm_data)

realm_key = "#{realm_data}/realm.key"

raise "Realm key #{realm_key} does not exist!" unless File::exist?(realm_key)

realm_principals = "#{realm_data}/principals"

raise "Realm principals directory #{realm_principals} not found!" unless File::directory?(realm_principals)

tmpdir = Dir::mktmpdir("kdc-transient")

kdc_conf = "#{tmpdir}/kdc.conf"
db_path = "#{tmpdir}/realm.db"

kdc_data = <<~KDCCONF
  [kdc]
    database = {
      realm = #{realm}
      dbname = sqlite:#{db_path}
      mkey_file = #{realm_key}
      log_file = /dev/null
    }

  [libdefaults]
    default_realm = #{realm}
    allow_weak_crypto = false
    default_etypes = #{options[:etypes].join(' ')}

  [kadmin]
    default_keys = aes256-cts-hmac-sha1-96:pw-salt

  [logging]
    kdc = FILE:#{tmpdir}/kdc.log
    default = FILE:#{tmpdir}/default.log
KDCCONF

File::open(kdc_conf, 'w') { |file| file.puts kdc_data }

def format_output(out)
  out.split('\n').map { |line| " > #{line}" }.join('\n')
end

def exec!(verbose, msg, cmd)
  puts msg if verbose
  print "  $ #{cmd} ... " if verbose
  out, status = Open3::capture2e(cmd)
  puts((status.success? ? 'success.' : 'failed!')) if verbose
  puts format_output(out) if verbose

  raise "failed execution of '#{cmd}': #{out}'" unless status.success?

  status.success?
end

# exec!(verbose, "Instantiating database at #{db_path}",
#       "kadmin -c #{kdc_conf} -- init #{realm}")

puts "Loading principals ... " if verbose
Dir["#{realm_principals}/*.key"].each do |principal|
  exec!(verbose, "  ... #{File::basename principal}",
        "kadmin --local --config-file=#{kdc_conf} -- merge #{principal}")
end

puts kdc_conf
