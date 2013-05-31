require "logger"
require "configliere"
require "sequel"

def configure
  Settings.use :commandline
  Settings(:db_url => "mysql://user:password@localhost/drupal",
           :match_text => "%blocked by CAPTCHA%",
           :minimum_matches => 20,
           :dry_run => false,
           :whitelist => [],
           :log_level => "info")
  #Settings.read File.join(File.dirname(__FILE__), "autoblock.yaml")
  Settings.read "autoblock.yaml"
  Settings.resolve!

  @db = Sequel.connect(Settings[:db_url])
  @log = Logger.new(STDOUT)
  @log.formatter = proc do |severity, datetime, progname, msg|
    "#{datetime.strftime('%Y-%m-%d %H:%M:%S')} [#{severity}] #{msg}\n"
  end
  @log.level = case Settings[:log_level].downcase
               when "fatal"
                 Logger::Fatal
               when "error"
                 Logger::ERROR
               when "warn"
                 Logger::WARN
               when "info"
                 Logger::INFO
               when "debug"
                 Logger::DEBUG
               end
end

def find_blockable
  blocked_ips = @db[:blocked_ips].select(:ip)
  @log.debug "blocked_ips SQL: #{blocked_ips.sql}"
  @log.info "Currently blocked: #{blocked_ips.count}"

  @log.info "Matching the watchdog.message field against: #{Settings[:match_text]}"

  selected = @db[:watchdog].where(Sequel.like(:message, Settings[:match_text]))
  @log.debug "selected SQL: #{selected.sql}"
  @log.info "Total matching records: #{selected.count}"

  selected_unblocked = selected.exclude(:hostname => blocked_ips)
  @log.debug "selected_unblocked SQL: #{selected_unblocked.sql}"
  @log.info "Blockable hosts: #{selected_unblocked.distinct.select(:hostname).count}"

  not_whitelisted = selected_unblocked.exclude(:hostname => Settings[:whitelist])
  @log.debug "not_whitelisted SQL: #{not_whitelisted.sql}"
  @log.info "Blockable hosts not in whitelist: #{not_whitelisted.distinct.select(:hostname).count}"

  blockable = not_whitelisted.
    group_and_count(:hostname).
    having { count >= Settings[:minimum_matches] }
  @log.debug "blockable SQL: #{blockable.sql}"
  @log.info "Blockable hosts with minimum #{Settings[:minimum_matches]} matches: #{blockable.count}"

  blockable.map(:hostname)
end

def block(ips)
  if ips.empty?
    @log.info "No hosts to block"
    return
  end

  @db.transaction do
    ips.each do |ip|
      @log.debug @db[:blocked_ips].insert_sql(:ip => ip)
      @db[:blocked_ips].insert(:ip => ip) unless Settings[:dry_run]
    end
  end
  @log.info (Settings[:dry_run] ? "[dry run] Would have blocked: " : "Blocked: ") + ips.join(', ')
end

configure
block(find_blockable)
