# frozen_string_literal: true

require 'open3'
require 'optparse'

options = {
  all_keys: false,
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "usage: #{File::basename $PROGRAM_NAME} [options] <principal0> ... <principal1> ..."

  opts.on("-c", "--conf CONFFILE", "File containing realm configuration.") { |conffile|
    options[:conf] = conffile
  }

  opts.on("-k", "--keytab KEYTAB", "Keytab into which keys will be extracted.") { |keytab|
    options[:keytab] = keytab
  }

  opts.on("-h", "--help", "Print this message.") {
    puts opts
    exit(0)
  }

  opts.on('-v', '--verbose', 'Provide verbose output.') do
    options[:verbose] = true
  end
end.parse!

def get_opt(opts, key, env = nil)
  if opts.key? key
    opts[key]
  elsif ENV.key? env
    ENV[env]
  else
    raise "missing required argument: #{key}"
  end
end

verbose = options[:verbose]

raise "Missing required argument: PRINCIPAL0" unless ARGV.length.positive?

principals = ARGV

config = get_opt(options, :conf, "KRB5_CONF")
raise "Config file not accessible: #{config}" unless File::readable?(config)

raise "Missing required argument: KEYTAB" unless options[:keytab]

def exec!(verbose, msg, cmd)
  puts msg if verbose
  print "  $ #{cmd} ... " if verbose
  out, status = Open3::capture2e(cmd)
  puts((status.success? ? 'success.' : 'failed!')) if verbose

  raise "failed execution of '#{cmd}': #{out}'" unless status.success?

  status.success?
end

puts "Extracting keytab ..." if verbose

principals.each { |princ|
  exec!(verbose, "  ... #{princ}",
        ["kadmin",
         "--local",
         "--config-file=#{config}",
         "--",
         "ext_keytab",
         "--keytab=#{options[:keytab]}",
         princ].join(" "))
}
