# frozen_string_literal: true

require 'fileutils'
require 'open3'
require 'optparse'
require 'tmpdir'

options = {
  etypes: %w[aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96],
  max_ticket_lifetime: "1w",
  max_renewable_lifetime: "1m",
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "usage: #{File::basename $PROGRAM_NAME} [options] <REALM_NAME>"

  opts.on('-e', '--encryption-types TYPES', 'Comma-separated list of default encryptions for the realm.') do |etypes|
    options[:etypes] = etypes.split(',')
  end

  opts.on('-m', '--max-ticket-lifetime LIFETIME',
          'Maximum lifetime for a ticket in this realm.') do |lifetime|
    options[:max_ticket_lifetime] = lifetime
  end

  opts.on('-r', '--max-renewable-lifetime LIFETIME',
          'Maximum renewal lifetimefor a ticket in this realm.') do |lifetime|
    options[:max_renewable_lifetime] = lifetime
  end

  opts.on('-o', '--output PATH', 'Path at which to store realm data.') do |path|
    options[:output_path] = path
  end

  opts.on('-v', '--verbose', 'Provide verbose output.') {
    options[:verbose] = true
  }

  opts.on('-h', '--help', 'Show this message.') do
    puts(opts)
    exit(0)
  end
end.parse!

verbose = options[:verbose]

raise 'missing required parameter: REALM_NAME' unless ARGV.length == 1

realm = ARGV[0]

if options[:output_path] && File::directory?(options[:output_path])
  output_path = options[:output_path]
elsif ENV.key?('KERBEROS_REALM_PATH')
  output_path = ENV['KERBEROS_REALM_PATH']
else
  raise 'missing required parameter: OUTPUT'
end

raise "output path does not exist: #{output_path}" unless File::directory?(output_path)

data_path = "#{output_path}/#{realm}"

key_path = "#{data_path}/realm.key"

raise "realm already initialized, #{key_path} exists!" if File::exist?(key_path)

tmpdir = Dir::mktmpdir("kdc-init")

key_tmp_path = "#{tmpdir}/realm.key"
db_tmp_path = "#{tmpdir}/realm.db"

kdc_data = <<~KDCCONF
  [kdc]
    database = {
      realm = #{realm}
      dbname = sqlite:#{db_tmp_path}
      mkey_file = #{key_tmp_path}
      log_file = /dev/null
    }

  [libdefaults]
    default_realm = #{realm}
    allow_weak_crypto = false
    default_etypes = #{options[:etypes].join(' ')}

  [logging]
    kdc = FILE:#{tmpdir}/kdc.log
    default = FILE:#{tmpdir}/default.log
KDCCONF

kdc_conf = "#{tmpdir}/kdc.conf"
puts "Writing kdc.conf: #{kdc_conf}" if verbose
File::open(kdc_conf, "w+") do |file|
  file.puts(kdc_data)
end

def format_output(out)
  out.split('\n').map { |line| " > #{line}" }.join('\n')
end

def exec!(verbose, msg, cmd)
  puts msg if verbose
  print " $ #{cmd} ... " if verbose
  out, status = Open3::capture2e(cmd)
  puts((status.success? ? 'success.' : 'failed!')) if verbose
  puts format_output(out) if verbose

  raise "failed execution of '#{cmd}': #{out}'" unless status.success?

  status.success?
end

def mvv(verbose, src, dst)
  print "  ... #{File::basename src} -> #{dst} ... " if verbose
  FileUtils::mv(src, dst)
  puts "done." if verbose
end

def rmv(verbose, filename)
  print "  ... #{File::basename filename} ..." if verbose
  File::delete(filename)
  puts "done." if verbose
end

exec!(verbose, "Creating realm key at #{key_tmp_path}",
      "kstash --key-file=#{key_tmp_path} --random-key")

exec!(verbose, "Initializing database at #{db_tmp_path}",
      ["kadmin --local",
       "--config-file=#{kdc_conf}",
       "init",
       "--realm-max-ticket-life=#{options[:max_ticket_lifetime]}",
       "--realm-max-renewable-life=#{options[:max_renewable_lifetime]} #{realm}"].join(" "))

dump_file = "#{tmpdir}/dumpfile"
principals_tmp = "#{tmpdir}/principals"
Dir::mkdir(principals_tmp)

exec!(verbose, "Dumping and decrypting database from #{db_tmp_path} to #{dump_file}",
      "kadmin --local --config-file=#{kdc_conf} dump --decrypt #{dump_file}")

puts("Extracting principals from database dumpfile #{dump_file} ...") if verbose
File::open(dump_file) do |f|
  f.readlines.each do |line|
    principal = line.split(' ')[0].gsub('/', '_')
    principal_file = "#{principals_tmp}/#{principal}.key"
    puts("  ... #{File::basename principal_file}") if verbose
    File::write(principal_file, line)
  end
end

principals = "#{data_path}/principals"

Dir::mkdir(data_path) unless File::directory?(data_path)
Dir::mkdir(principals) unless File::directory?(principals)

puts "Moving realm data to #{data_path}" if verbose
mvv(verbose, key_tmp_path, key_path)
puts '  Principals ...' if verbose
Dir["#{principals_tmp}/*.key"].each { |princ_src|
  princ = File::basename(princ_src)
  princ_dst = "#{principals}/#{princ}"
  mvv(verbose, princ_src, princ_dst)
  FileUtils::chmod(0o400, princ_dst)
}

puts "Removing working data ..." if verbose
rmv(verbose, db_tmp_path)
rmv(verbose, dump_file)
puts if verbose
puts "Realm #{realm} initialized!" if verbose
