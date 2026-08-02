# frozen_string_literal: true

# Manually add a specified principal

require 'open3'
require 'optparse'
require 'tmpdir'

options = {
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "usage: #{File::basename $PROGRAM_NAME} [opts] <PRINCIPAL>"

  opts.on("-c", "--conf CONFFILE", "File containing realm configuration.") do |conffile|
    raise "CONFFILE does not exist: #{conffile}" unless File::exist?(conffile)

    options[:conf] = conffile
  end

  opts.on("-p", "--principal-dir PRINCIPAL_DIR", "Path at which to save principal keys.") do |principals|
    raise "PRINCIPAL_DIR does not exist: #{principals}" unless File::directory?(principals)

    options[:principals] = principals
  end

  opts.on("-w", "--password PASSWORD",
          "Password to set for the principal. If not specified, a random key will be set.") do |password|
    options[:password] = password
  end

  opts.on("-h", "--help", "Print this message.") do
    puts opts
    exit(0)
  end

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
  puts "missing required parameter PRINCIPAL!"
  Kernel::exit(false)
else
  principal = ARGV[0]
end

verbose = options[:verbose]

principal_path = get_opt(options, :principals, "KRB5_PRINCIPAL_DIR")
config = get_opt(options, :conf, "KRB5_CONF")

principal_filename = principal.sub("/", "_")
output_filename = "#{principal_path}/#{principal_filename}.key"

raise "principal key exists: #{output_filename}" if File::exist?(output_filename)

def exec!(verbose, msg, cmd)
  puts msg if verbose
  print "  $ #{cmd} ... " if verbose
  out, status = Open3::capture2e(cmd)
  puts((status.success? ? 'success.' : 'failed!')) if verbose

  raise "failed execution of '#{cmd}': #{out}'" unless status.success?

  status.success?
end

principal_keys = Dir::mktmpdir("add_principals") do |tmpdir|
  pw_clause = if options[:password]
                "--password=\"#{options[:password]}\""
              else
                "--random-key"
              end
  exec!(verbose, " ... #{principal}",
        ["kadmin",
         "--local",
         "--config-file=#{config}",
         "--",
         "add",
         pw_clause,
         "--use-defaults",
         principal].join(" "))
  dump_file = "#{tmpdir}/dumpfile"
  exec!(verbose, "Extracting keys ...",
        "kadmin --local --config-file=#{config} -- dump --decrypt #{dump_file}")
  File::open(dump_file, "r") do |file|
    file.readlines.filter { |line|
      princ = line.split(" ")[0]
      princ == principal
    }
  end
end

print("Writing principal key to #{output_filename} ... ") if verbose

File::open(output_filename, 'w') do |f|
  principal_keys.each { |line|
    f.puts(line)
  }
end

puts "done." if verbose
