# frozen_string_literal: true

# Given an existing KDC database DB and a file containing principals PRINCIPALS,
# create a new database containing the principals in PRINCIPALS, along with any
# additional principals from DB which do not exist in PRINCIPALS.
#
# This allows the server to maintain an authoritative list of keys for most
# entities (mostly, hosts) while allowing for the creation and update of users.

require 'open3'
require 'optparse'
require 'tempfile'
require 'tmpdir'

options = {
  verbose: false
}

def expand_env_var(str)
  str.gsub(/\$\w+/) { |var| ENV[var[1..]] }
end

OptionParser.new do |opts|
  opts.on('-c', '--create', 'Create database file.') do
    options[:create] = true
  end

  opts.on('-d', '--database DATABASE', 'Path to the existing KDC database file.') do |file|
    options[:existing_db] = expand_env_var file
  end

  opts.on('-p', '--principals PRINCIPALS', 'Path to file containing incoming principals.') do |file|
    raise "File inaccessible: #{file}" unless File::readable?(file)

    options[:incoming_principals] = expand_env_var file
  end

  opts.on('-k', '--key KEY', 'Path to realm key file.') do |file|
    raise "File inaccessible: #{file}" unless File::readable?(file)

    options[:key] = expand_env_var file
  end

  opts.on('-r', '--realm REALM', 'Name of the KDC realm.') do |realm|
    options[:realm] = realm
  end

  opts.on('-v', '--verbose', "Provide verbose output.") do
    options[:verbose] = true
  end
end.parse!

raise "missing required parameter: KEY" unless options[:key]

raise "missing required parameter: REALM" unless options[:realm]

raise "missing required parameter: PRINCIPALS" unless options[:incoming_principals]

raise "missing required parameter: DATABASE" unless options[:existing_db]

verbose = options[:verbose]

# rubocop:disable Metrics/MethodLength
def generate_kdc(realm, db, key, tmp)
  conf_file = "#{tmp}/kdc.conf"
  data = <<~KDC_CONF
    [kdc]
      database = {
        realm = #{realm}
        dbname = sqlite:#{db}
        mkey_file = #{key}
        log_file = /dev/null
      }

    [libdefaults]
      default_realm = #{realm}
      allow_weak_crypto = false

    [logging]
      default = CONSOLE
  KDC_CONF
  File::write(conf_file, data)
  conf_file
end
# rubocop:enable Metrics/MethodLength

def exec!(verbose, msg, cmd)
  puts msg if verbose
  print "  $ #{cmd} ... " if verbose
  out, status = Open3::capture2e(cmd)
  puts((status.success? ? 'success.' : 'failed!')) if verbose

  raise "failed execution of '#{cmd}': #{out}" unless status.success?

  status.success?
end

def read_principals(verbose, file)
  puts "reading from #{file}:" if verbose
  File::open(file, 'r') do |f|
    f.readlines.each_with_object({}) do |line, coll|
      princ = line.split(" ")[0]
      puts "  ... #{princ}" if verbose
      coll[princ] = line.strip
    end
  end
end

def read_database_principals(verbose, realm, db, key)
  return {} unless File::exist? db

  puts "database exists: #{db}" if verbose
  Dir::mktmpdir('existing-kdc') do |tmpdir|
    conf = generate_kdc(realm, db, key, tmpdir)
    dump = "#{tmpdir}/dumpfile"
    exec!(verbose, "Dumping existing database ...",
          "kadmin --local --config-file=#{conf} -- dump --decrypt #{dump}")
    read_principals(verbose, dump)
  end
end

existing_principals = read_database_principals(verbose,
                                               options[:realm],
                                               options[:existing_db],
                                               options[:key])

incoming_principals = read_principals(verbose, options[:incoming_principals])

missing_principals = existing_principals.keys - incoming_principals.keys

puts "restoring principals: #{missing_principals.join(',')}" if verbose

database_contents = incoming_principals

missing_principals.each { |k|
  database_contents[k] = existing_principals[k]
}

def write_to_dump(verbose, dumpfile, dumpdata)
  puts 'Preparing database ...' if verbose
  File::open(dumpfile, 'w') do |file|
    dumpdata.each_pair do |princ, data|
      puts "  ... #{princ}" if verbose
      file.puts(data)
    end
  end
end

def move_db(verbose, src, dst)
  print "Changing ownership of #{src} ... " if verbose
  FileUtils::chmod(0o600, src)
  puts "done." if verbose
  print "Moving database #{src} -> #{dst} ... " if verbose
  FileUtils::mv(src, dst)
  puts "done." if verbose
end

Dir::mktmpdir("kdc-database") do |tmpdir|
  puts "Preparing database ..." if verbose
  dump = "#{tmpdir}/realm.dump"
  db = "#{tmpdir}/realm.db"
  conf = generate_kdc(options[:realm], db, options[:key], tmpdir)
  write_to_dump(verbose, dump, database_contents)
  exec!(verbose, "Building database ...",
        "kadmin --local --config-file=#{conf} -- load #{dump}")
  move_db(verbose, db, options[:existing_db])
end
