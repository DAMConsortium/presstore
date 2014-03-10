require 'rubygems'
require 'net/ssh'
require 'open3'
require 'shellwords'
require 'socket'
require 'plist'

module PresSTORE

  class API

    DEFAULT_ARCHIVE_PLAN_ID = '10001'
    DEFAULT_CLIENT_NAME = 'localhost'
    DEFAULT_ARCHIVE_DATABASE_NAME = 'Default-Archive'

    DEFAULT_NSDCHAT_CMD_PATH = '/usr/local/aw/bin/nsdchat'
    DEFAULT_USERNAME = 'admin'
    DEFAULT_PASSWORD = 'password'
    DEFAULT_SERVER_ADDRESS = 'localhost:9001'

    DEFAULT_USE_SSH = false

    attr_accessor :logger
    attr_reader :use_ssh, :ssh_settings
    attr_reader :request, :response

    attr_reader :initial_params

    # @params [Hash] params
    # @option params [Object] :logger (Logger.new(STDOUT))
    # @option params [String] :ndschat_cmd_path ('/usr/local/aw/bin/nsdchat')
    # @option params [String] :presstore_username ('admin')
    # @option params [String] :presstore_password ('password')
    # @option params [String] :presstore_server_address ('localhost:9001')
    # @option params [Boolean] :use_ssh (false)
    # @option params [Hash] :ssh_settings { hostname: 'localhost', username: 'username', password: 'password' }
    def initialize(params = {})
      params = params.dup
      @logger = params.delete(:logger) { Logger.new(STDOUT) }
      @initial_params = params.dup.freeze
      set_connection(params)
    end # initialize

    def instance_session
      @instance_session ||= "RUBY-#{Socket.gethostname}-#{Time.now.to_i}"
    end

    def ssh_settings=(value)
      @ssh_settings = value
      validate_ssh
    end # ssh_settings=

    def use_ssh=(value)
      @use_ssh = value
      validate_ssh
    end # use_ssh

    def validate_ssh
      unless ssh_settings.is_a?(Hash) and ssh_settings[:hostname] and ssh_settings[:username]
        @use_ssh = false
        @ssh_settings ||= { }
        logger.warn { "Use SSH is set to true but required parameters are missing. Hostname: '#{ssh_settings[:hostname]}' Username: '#{ssh_settings[:username]}'" }
      end if @use_ssh
    end # validate_ssh

    def set_connection(params)
      @request = ''
      @response = { }
      @error = ''
      @error_occurred = false

      params = initial_params.merge(params)
      logger.debug { "#{__method__} Setting Connection. #{params}" }

      _ssh_settings = params[:ssh_settings]
      unless _ssh_settings
        logger.debug { "#{__method__} :ssh_settings not found. #{ssh_settings}" }
        ssh_hostname = params[:ssh_hostname]
        ssh_username = params[:ssh_username]
        ssh_password = params[:ssh_password]

        _ssh_settings = { }
        _ssh_settings[:hostname] = ssh_hostname if ssh_hostname
        _ssh_settings[:username] = ssh_username if ssh_username
        _ssh_settings[:password] = ssh_password if ssh_password
      else
        logger.debug { "#{__method__} :ssh_settings found. #{ssh_settings}" }
      end

      @ssh_settings = _ssh_settings
      @use_ssh = params[:use_ssh] || DEFAULT_USE_SSH
      logger.debug { "#{__method__} SSH Settings: #{ssh_settings}" }
      #build_base_command(params)
      set_base_command(params)
    end # set_connection

    def error?
      @error_occurred
    end # error?

    def reset_connection
      set_connection(initial_params)
    end # reset_connection

    # @params [Hash] params
    # @option params [String] :ndschat_cmd_path
    # @option params [String] :presstore_username
    # @option params [String] :presstore_password
    # @option params [String] :presstore_server_address
    def build_base_command(params = {})
      return @nsdchat if params.empty? unless !@nsdchat
      logger.debug { "Building base command. #{params}" }
      nsdchat_cmd_path = params[:nsdchat_cmd_path] || @nsdchat_cmd_path ||= DEFAULT_NSDCHAT_CMD_PATH
      base_command = [ nsdchat_cmd_path ]



      specify_server = params.fetch(:specify_server, nil)
      if specify_server or specify_server.nil?
        session = params[:presstore_session] || params[:session]
        server_address = params[:presstore_server_address] || params[:server_address]

        username = params[:presstore_username] || params[:username]
        password = params[:presstore_password] || params[:password]

        specify_server = (session or server_address or username or password)
      end
      if specify_server
        session ||= @session ||= instance_session
        server_address ||= @server_address ||= DEFAULT_SERVER_ADDRESS


        unless (username and !username.empty?) or (password and !password.empty?)
          username = @username ||= DEFAULT_USERNAME
          password = @password ||= DEFAULT_PASSWORD
          logger.debug { "Assigned Username: '#{username}' Password: '#{password}'" }
        else
          logger.debug { "Using Username: '#{username}' (Empty?: #{username and username.empty?}) Password: '#{password}'" }
        end

        base_command << '-s' << "awsock:/#{username}:#{password}:#{session}@#{server_address}"
      end

      base_command.shelljoin
    end # build_base_command

    def set_base_command(params = { })
      @nsdchat = build_base_command(params)
      logger.debug { "Base Command Set To: #{@nsdchat}" }
      @nsdchat
    end # set_base_command

    def command(*args)
      logger.debug { "COMMAND: #{args}"}
      params = args.pop if args.last.is_a? Hash
      params ||= { }

      nsdchat = build_base_command(params)
      #logger.debug { "#{__method__} Using Base Command: #{nsdchat}"}

      base_cmd_line = "#{nsdchat} -c"

      command_array = [*args]
      if command_array.first.is_a?(Array)
        logger.debug { "#{command_array}"}
        cmd_line = command_array.map { |cmd_ary| "#{base_cmd_line} #{cmd_ary.shelljoin}" }
      else
        command_string = command_array.shelljoin
        cmd_line = "#{base_cmd_line} #{command_string}"
      end

      response = execute(cmd_line)
      response.is_a?(Array) ? response.map { |r| r[:stdout] } : response[:stdout]
    end

    def simple_command_execute(command, *args)
      cmd_ary = [ @nsdchat, '-c', command ]

    end

    def nsdchat_version(params = {})
      set_connection(params)
      cmd_line = "#{@nsdchat} -v"
      execute(cmd_line)
    end

    def get_error
      @error = command('geterror')
    end

    # @return [Array] Returns an array of client names
    def client_names
      command('Client', 'names')
    end

    # @return [Array] Returns an array of archive plan names
    def archive_plan_names
      command('ArchivePlan', 'names')
    end

    def archive_entry_btime(name)
      cmd_line = "#{@nsdchat} -c ArchiveEntry {#{escape_path(name)}} btime"
      response = execute(cmd_line)
      stdout = response[:stdout]
      return false unless response[:success] and !stdout.empty?

      stdout
    end

    def archive_entry_meta(name)
      cmd_line = "#{@nsdchat} -c ArchiveEntry {#{escape_path(name)}} meta"
      response = execute(cmd_line)
      stdout = response[:stdout]
      return false unless response[:success] and !stdout.empty?

      stdout
    end

    def archive_entry_mtime(name)
      cmd_line = "#{@nsdchat} -c ArchiveEntry {#{escape_path(name)}} status"
      response = execute(cmd_line)
      stdout = response[:stdout]
      return false unless response[:success] and !stdout.empty?

      stdout
    end

    def archive_entry_size(name)
      cmd_line = "#{@nsdchat} -c ArchiveEntry {#{escape_path(name)}} status"
      response = execute(cmd_line)
      stdout = response[:stdout]
      return false unless response[:success] and !stdout.empty?

      stdout
    end

    def archive_entry_status(name)
      cmd_line = "#{@nsdchat} -c ArchiveEntry {#{escape_path(name)}} status"
      response = execute(cmd_line)
      stdout = response[:stdout]
      return false unless response[:success] and !stdout.empty?

      stdout
    end


    ##### ARCHIVE METHODS #####


    # @param [String] archive_plan_id This must be one of the registered archive plans
    # @param [String] client_name This must be one of the registered client computers on the current PresSTORE server.
    def archive_selection_create(archive_plan_id = DEFAULT_ARCHIVE_PLAN_ID, client_name = DEFAULT_CLIENT_NAME)
      logger.debug { "Creating Archive Selection. Archive Plan: #{archive_plan_id} Client Name: #{client_name}"}
      cmd_line = "#{@nsdchat} -c ArchiveSelection create #{client_name} #{archive_plan_id}"
      response = execute(cmd_line)
      return false unless response[:success]

      archive_selection_name = response[:stdout]

      archive_selection_name
    end # archive_selection_create

    def escape_path(path)
      path = path.dup
      path.gsub!('{', '\{')
      path.gsub!('}', '\}')
      path.gsub!('&', '\\\&')
      path
    end

    def archive_selection_add_entry(archive_selection_name, asset_full_file_path)
      logger.debug { "Adding Entry: #{asset_full_file_path} to #{archive_selection_name}" }
      cmd_line = "#{@nsdchat} -c ArchiveSelection #{archive_selection_name} addentry {#{escape_path(asset_full_file_path)}}"
      response = execute(cmd_line)
      # Received exit code 100 when the file being added did not exist
      return false unless response[:success] and !response[:stdout].empty?

      archive_entry_name = response[:stdout]

      archive_entry_name
    end

    def archive_selection_submit(archive_selection_name)
      cmd_line = "#{@nsdchat} -c ArchiveSelection #{archive_selection_name} submit yes"
      response = execute(cmd_line)
      return false unless response[:success] and !response[:stdout].empty?

      job_resource = response[:stdout]

      logger.debug { "Submit Selection Response: #{response}" }
      job_resource
    end # archive_selection_submit

    def archive_selection_destroy(archive_selection_name)
      cmd_line = "#{@nsdchat} -c ArchiveSelection #{archive_selection_name} destroy"
      response = execute(cmd_line)
      return true if response[:stdout] == 0
      return false # unless response[:success] and !response[:stdout].empty?
    end # archive_selection_destroy

    def archive_entry_volume_name(handle)
      cmd_line = "#{@nsdchat} -c ArchiveEntry #{handle} volume"
      response = execute(cmd_line)
      return false unless response[:success] and !response[:stdout].empty?

      logger.debug { "ArchiveEntry Volume Response: #{response}" }
      volume_name = response[:stdout]

      volume_name
    end # archive_entry_volume

    def volume_barcode(volume_name)
      cmd_line = "#{@nsdchat} -c Volume #{volume_name} barcode"
      response = execute(cmd_line)
      return false unless response[:success]

      logger.debug { "Volume Barcode Response: #{response}" }
      barcode = response[:stdout]

      barcode
    end

    def archive_begin(params = { }, options = { })
      set_connection(params)
      archive_plan_id = params[:archive_plan_id] || DEFAULT_ARCHIVE_PLAN_ID
      selection_name = archive_selection_create(archive_plan_id)
      #raise "Error Creating Archive Selection. Request: #{@request} Response: #{@response}" unless selection_name
      selection_name
    end

    # @params [Hash] params
    # @option params [String] :asset_full_file_path REQUIRED The full file path of the file to archive
    # @option params [String] :archive_plan_id ('10001')
    def archive(params = { }, options = { })
      asset_full_file_path = params.fetch(:asset_full_file_path, false)
      return false unless asset_full_file_path

      #@nsdchat = create_base_command(params)
      #archive_plan_id = params.fetch(:archive_plan_id, DEFAULT_ARCHIVE_PLAN_ID)
      #archive_plan = ArchivePlan.new(archive_plan_id)
      #archive_selection = ArchiveSelection.create(archive_plan)
      #archive_entry_name = archive_selection.addentry(asset_full_file_path)
      #archive_selection.submit

      selection_name = archive_begin(params)
      raise "Error Creating Archive Selection. Request: #{@request} Response: #{@response}" unless selection_name

      ignore_empty_archive_handles = options.fetch(:ignore_empty_archive_handles, false)

      entries = [ ]
      [*asset_full_file_path].each do |path|

        name = archive_selection_add_entry(selection_name, path)

        # When an error occurs we get an empty string back
        raise "Error Adding Entry to Archive Selection. #{path}" unless ignore_empty_archive_handles or !name or !name.empty?
        entries << { :path => path, :name => name }
      end

      logger.debug { "Submitting Archive Selection #{selection_name} for Archive."}
      job_id = archive_selection_submit(selection_name)

      response = { :job_id => job_id, :selection_name => selection_name, :entries => entries }

      logger.debug { 'Archive Submitted.' }
      response
    end

    ##### RESTORE METHODS #####

    # @param [String] path The absolute platform-native path to a file.
    # @param [Hash] params ({ })
    # @option params [String] :client_name This must be one of the registered client computers on the current PresSTORE server.
    # @option params [String] :database_name The name of the database where the file has been indexed.
    # @return [String] archive_entry_handle
    def archive_entry_handle(path, params = { })
      params = params.dup
      client_name = params.delete(:client_name) { DEFAULT_CLIENT_NAME }
      database_name = params.delete(:database_name) { DEFAULT_ARCHIVE_DATABASE_NAME }
      set_connection(params)
      logger.debug { "Getting Entry Archive Handle for: #{path}"}
      cmd_line = "#{@nsdchat} -c ArchiveEntry handle #{client_name} {#{escape_path(path)}} #{database_name} "
      response = execute(cmd_line)
      return false unless response[:success]

      _archive_entry_handle = response[:stdout]

      _archive_entry_handle
    end

    # Creates new temporary restore selection resource.
    #
    # @param [String] client_name This must be one of the registered client computers on the current PresSTORE server.
    def restore_selection_create(client_name = DEFAULT_CLIENT_NAME)
      cmd_line = "#{@nsdchat} -c RestoreSelection create #{client_name}"
      response = execute(cmd_line)
      return false unless response[:success]

      restore_selection_name = response[:stdout]

      restore_selection_name
    end

    # @param [String] restore_selection_name
    # @param [String] archive_entry_handle
    def restore_selection_add_entry(restore_selection_name, archive_entry_handle)
      cmd_line = "#{@nsdchat} -c RestoreSelection #{restore_selection_name} addentry #{archive_entry_handle}"
      response = execute(cmd_line)
      return false unless response[:success]

      archive_entry_file_path = response[:stdout]

      archive_entry_file_path
    end # restore_selection_add_entry

    def restore_selection_submit(restore_selection_name)
      cmd_line = "#{@nsdchat} -c RestoreSelection #{restore_selection_name} submit 0"
      response = execute(cmd_line)
      return false unless response[:success]

      job_id = response[:stdout]

      job_id
    end # restore_selection_submit

    def restore_selection_destroy(restore_selection_name)
      cmd_line = "#{@nsdchat} -c RestoreSelection #{restore_selection_name} destroy"
      response = execute(cmd_line)
      return true if response[:stdout] == 0
      return false # unless response[:success] and !response[:stdout].empty?
    end

    def retrieve_begin(params = { }, options = { })
      set_connection(params)
      selection_name = restore_selection_create
      selection_name
    end

    def retrieve_add_entry(selection_name, params)
      handle = params.fetch(:archive_entry_handle, false)
      asset_full_file_path = params.fetch(:asset_full_file_path, false)
      handle ||= archive_entry_handle(asset_full_file_path)

      restore_selection_add_entry(selection_name, handle)
    end

    def retrieve(params = { }, options = { })
      archive_entry_handle = params.fetch(:archive_entry_handle, false)
      asset_full_file_path = params.fetch(:asset_full_file_path, false)
      return { :error => true, :response => 'Missing parameter. :asset_full_file_path or :archive_entry_handle is required.' } unless asset_full_file_path or archive_entry_handle

      #archive_entry = ArchiveEntry.handle(asset_full_file_path)
      #restore_selection = RestoreSelection.create
      #RestoreSelection.add_entry(archive_entry)
      #job_id = RestoreSelection.submit

      entry_handles = [ ]
      [*archive_entry_handle].each { |handle| entry_handles << handle if handle }
      #[*asset_full_file_path].each { |path| entry_handles << { name: handle, path: archive_entry_handle(path) } if path }
      [*asset_full_file_path].each { |path| entry_handles << { :name => archive_entry_handle(path), :path => path } if path }

      set_connection(params)
      selection_name = restore_selection_create

      entries = [ ]
      entry_handles.each { |handle| entries << restore_selection_add_entry(selection_name, handle) }

      job_id = restore_selection_submit(selection_name)

      { :job_id => job_id, :selection_name => selection_name, :entries => entries }
    end # retrieve
    alias :restore :retrieve

    # @param [Integer] job_id
    def job_status(job_id)
      cmd_line = "#{@nsdchat} -c Job #{job_id} status"
      response = execute(cmd_line)
      return false unless response[:success]

      response[:stdout]
    end

    def job_pending
      cmd_line = "#{@nsdchat} -c Job pending"
      response = execute(cmd_line)
      return false unless response[:success]

      response[:stdout]
    end

    def jobs_pending_count(pending_jobs = nil)
      pending_jobs ||= job_pending
      return 0 unless pending_jobs
      return 0 if pending_jobs == '<empty>'
      return pending_jobs.lines.count
    end

    def job_running
      cmd_line = "#{@nsdchat} -c Job running"
      response = execute(cmd_line)
      return false unless response[:success]

      response[:stdout]
    end

    def job_completed(number_of_days = nil)
      cmd_line = "#{@nsdchat} -c Job completed"
      cmd_line << " #{sanitize_arg(number_of_days)}" if number_of_days
      response = execute(cmd_line)
      return false unless response[:success]

      response[:stdout]
    end

    def job_warning(number_of_days = nil)
      cmd_line = "#{@nsdchat} -c Job warning"
      cmd_line << " #{sanitize_arg(number_of_days)}" if number_of_days
      response = execute(cmd_line)
      return false unless response[:success]

      response[:stdout]
    end

    def job_failed(number_of_days = nil)
      cmd_line = "#{@nsdchat} -c Job failed"
      cmd_line << " #{sanitize_arg(number_of_days)}" if number_of_days
      response = execute(cmd_line)
      return false unless response[:success]

      response[:stdout]
    end

    def sanitize_arg(arg, *args)
      if args
        args.unshift(arg)
        return args.map { |arg| arg.respond_to?(:to_s) ? arg.to_s.shellescape : nil }
      else
        return arg.respond_to?(:to_s) ? arg.to_s.shellescape : nil
      end
    end
    alias :sanitize_args :sanitize_arg

    # @param [String] cmd_line The command line to execute
    # @return [Hash] { "STDOUT" => [String], "STDERR" => [String], "STATUS" => [Object] }
    def execute_sh(cmd_line)
      return cmd_line.map { |cl| execute_sh(cl) } if cmd_line.is_a?(Array)

      begin
        stdout_str, stderr_str, status = Open3.capture3(cmd_line)
        response = { :stdout => stdout_str.chomp!, :stderr => stderr_str.chomp!, :status => status, :success => status.success? }
      rescue
        logger.error { "Error Executing '#{cmd_line}'. Exception: #{$!} @ #{$@} STDOUT: '#{stdout_str}' STDERR: '#{stderr_str}' Status: #{status.inspect} " }
        response = { :stdout => stdout_str, :stderr => stderr_str, :status => status, :success => false }
      ensure
        logger.debug { "Response: #{response}" }
        return response
      end
    end

    def execute_ssh(command_line, ssh = ssh_settings)
      if ssh.is_a? Hash
        ssh = ssh.dup
        ssh = [ ssh.delete(:hostname), ssh.delete(:username), ssh ]
      else
        ssh ||= [ 'localhost', `whoami`, { } ]
      end

      if ssh.is_a? Array
        logger.debug { "Initializing SSH Connection: #{ssh}" }
        ssh = Net::SSH.start(*ssh)
        close_ssh = true
      end

      begin
        response = [ ]
        command_line.each { |current_command| response << execute_ssh(current_command, ssh) }
      ensure
        ssh.close if close_ssh
        return response
      end if command_line.is_a? Array

      #logger.debug { "Executing Command Line Using SSH\n#{ssh.inspect}\n: #{command_line}"}
      logger.debug { "Executing Command Line Using SSH: '#{command_line}'" }
      begin
        stdout_data, stderr_data, exit_code, exit_signal = '', '', nil, nil
        #response = { :stdout => stdout_data, :stderr => stderr_data, :exit_code => exit_code, :exit_signal => exit_signal, :success => !exit_code.nil? }

        ssh.open_channel do |channel|
          #logger.debug { "SSH Executing Command: '#{command_line}'" }
          channel.exec(command_line) do |_, success|
            raise "FAILED: couldn't execute command (#{command})" unless success

            channel.on_data { |_,data| stdout_data += data }
            channel.on_extended_data { |_, _,data| stderr_data += data }
            channel.on_request('exit-status') { |_,data| exit_code = data.read_long }
            channel.on_request('exit-signal') { |_, data| exit_signal = data.read_long }
          end
        end
        ssh.loop
        response = { :stdout => stdout_data.chomp!, :stderr => stderr_data.chomp!, :exit_code => exit_code, :exit_signal => exit_signal, :success => !exit_code.nil? }
      rescue => e
        response = { :stdout => stdout_data, :stderr => stderr_data, :exit_code => exit_code, :exit_signal => exit_signal, :success => false, :exception => e }
      ensure
        logger.debug { "Response: #{response}" }
        ssh.close if close_ssh
        return response
      end
    end # execute_ssh

    def execute(command_line, error_if_empty = false)
      @request = command_line
      if use_ssh #and ssh_settings.is_a?(Hash) and ssh_settings[:hostname]
        logger.debug { "Executing Command Line Using SSH: '#{command_line}')" }
        @response = execute_ssh command_line
      else
        logger.debug { "Executing Command Line Using Local Shell: '#{command_line}'" }
        @response = execute_sh command_line
      end
      #logger.debug { "Response: #{response}" }
      @error_occurred = true if error_if_empty and response[:stdout].empty?
      return response
    end


  end

end


