# frozen_string_literal: true

require 'open3'
require 'optparse'

options = {
  all_keys: false,
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "usage: #{File::basename $PROGRAM_NAME} [options] <hostname>"

  opts.on('-a', '--all', 'Extract all host keys into keytab. Overrides --services.') {
    options[:all_keys] = true
  }

  opts.on("-s", "--services SERVICE0,SERVICE1",
          "Host services to extract into a keytab. Comma-seperated.") { |services|
    options[:services] = services.split(",")
  }

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

raise "Missing required argument: HOSTNAME" unless ARGV.length == 1

hostname = ARGV[0]

config = get_opt(options, :conf, "KRB5_CONF")
raise "Config file not accessible: #{config}" unless File::readable?(config)

raise "Missing required argument: KEYTAB" unless options[:keytab]

raise "Missing required argument(s): SERVICES" unless options[:services] || options[:all_keys]

def exec!(verbose, msg, cmd)
  puts msg if verbose
  print "  $ #{cmd} ... " if verbose
  out, status = Open3::capture2e(cmd)
  puts((status.success? ? 'success.' : 'failed!')) if verbose

  raise "failed execution of '#{cmd}': #{out}'" unless status.success?

  status.success?
end

puts "Extracting keytab ..." if verbose

if options[:all_keys]
  princ = "*/#{hostname}"
  exec!(verbose, "  ... #{princ}",
        ["kadmin",
         "--local",
         "--config-file=#{config}",
         "--",
         "ext_keytab",
         "--keytab=#{options[:keytab]}",
         princ].join(" "))
else
  options[:services].each { |srv|
    princ = "#{srv}/#{hostname}"
    exec!(verbose, "  ... #{princ}",
          ["kadmin",
           "--local",
           "--config-file=#{config}",
           "--",
           "ext_keytab",
           "--keytab=#{options[:keytab]}",
           princ].join(" "))
  }
end
