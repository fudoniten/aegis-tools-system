# frozen_string_literal: true

require 'open3'
require 'optparse'
require 'tmpdir'

options = {
  services: %w[host ssh],
  verbose: false
}

OptionParser.new do |opts|
  opts.on("-s", "--services SERVICE0,SERVICE1",
          "Services for which to generate keys for this host. Comma-seperated.") { |services|
    options[:services] = services.split(",")
  }

  opts.on("-c", "--conf CONFFILE", "File containing realm configuration.") { |conffile|
    options[:conf] = conffile
  }

  opts.on("-p", "--principal-dir PRINCIPAL_DIR", "Path at which to save host key files.") { |principals|
    options[:principals] = principals
  }

  opts.on("-h", "--help", "Print this message.") {
    puts "usage: #{File::basename $PROGRAM_NAME} [opts] <hostname>"
    puts opts
    exit(0)
  }

  opts.on('-v', '--verbose', 'Provide verbose output.') do
    options[:verbose] = true
  end
end.parse!

def get_opt(opts, key, env = nil)
  if opts.key?(key)
    opts[key]
  elsif ENV.key?(env)
    ENV[env]
  else
    raise "missing required argument: #{key}"
  end
end

if ARGV.length != 1
  puts "hostname argument required!"
  Kernel::exit(false)
else
  hostname = ARGV[0]
end

verbose = options[:verbose]

service_list = options[:services]
puts "Generating keys for services: #{service_list.join(' ')}" if verbose

config = get_opt(options, :conf, "KRB5_CONF")

raise "Config file does not exist: #{config}" unless File::exist?(config)

principal_path = get_opt(options, :principals, "KRB5_PRINCIPAL_DIR")

raise "Principal output directory does not exist: #{principal_path}" unless File::directory?(principal_path)

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

def exec_code!(verbose, msg, cmd)
  puts msg if verbose
  print "  $ #{cmd} ... " if verbose
  _, status = Open3::capture2e(cmd)
  status.success?
end

def exists?(verbose, config, princ)
  exec_code!(verbose, "  ... check existence of #{princ}",
             ["kadmin --local",
              "--config-file=#{config}",
              "--",
              "get",
              princ].join(" "))
end

def add_key(verbose, config, princ)
  exec!(verbose, "  ... adding key for #{princ}",
        ["kadmin --local",
         "--config-file=#{config}",
         "--",
         "add",
         "--random-key",
         "--use-defaults",
         princ].join(" "))
end

principals = Dir::mktmpdir("host_principals") do |tmpdir|
  puts "Adding keys for host #{hostname} ..." if verbose
  service_list.each { |srv|
    princ = "#{srv}/#{hostname}"
    if exists?(verbose, config, princ)
      puts "  ... exists, skipping"
    else
      add_key(verbose, config, princ)
    end
  }

  dump_file = "#{tmpdir}/dumpfile"

  exec!(verbose, "Extracting principals ...",
        "kadmin --local --config-file=#{config} -- dump --decrypt #{dump_file}")

  File::open(dump_file, "r") do |file|
    file.readlines.each_with_object({}) { |line, princs|
      princ = line.split(" ")[0].split("@")[0]
      princs[princ] = line.strip
    }
  end
end

puts("Writing principal keys to #{principal_path}") if verbose

service_list.each do |srv|
  princ = "#{srv}/#{hostname}"
  print "  ... #{princ} ... " if verbose
  filename = "#{principal_path}/#{srv}_#{hostname}.key"
  if File::exist?(filename)
    puts "skipping existing principal #{princ}." if verbose
    next
  end
  File::open(filename, "w") do |f|
    f.puts(principals[princ])
  end
  puts "done." if verbose
end
