# frozen_string_literal: true

# name: discourse-password-reset-webhook
# about: Sends form-urlencoded webhook to PHP endpoint when password reset is requested and when it is completed (async via Sidekiq).
# version: 1.5.0
# authors: you

after_initialize do
  require "uri"
  require "digest"
  require "net/http"
  require "time"

  module ::PasswordResetWebhook
    PLUGIN_NAME = "discourse-password-reset-webhook"

    # =========================
    # CONFIG (EDIT THESE)
    # =========================
    ENDPOINT_URL  = "http://172.17.0.1:8081/password_reset_update.php"
    SECRET_FIELD  = ""  # optional; sent as form field "secret" if not blank
    TIMEOUT_SEC   = 3   # read timeout
    OPEN_TIMEOUT  = 2   # connect timeout
    WRITE_TIMEOUT = 3   # only if supported
    ENABLED       = true
    DEBUG_LOG     = false
    # =========================

    def self.dlog(msg)
      return unless DEBUG_LOG
      Rails.logger.warn("[#{PLUGIN_NAME}] DEBUG #{msg}")
    rescue StandardError
    end

    def self.log_warn(msg)
      Rails.logger.warn("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.endpoint_uri
      @endpoint_uri ||= begin
        s = ENDPOINT_URL.to_s.strip
        return nil if s.empty?
        URI.parse(s)
      rescue StandardError
        nil
      end
    end

    def self.enabled?
      return false unless ENABLED
      uri = endpoint_uri
      return false if uri.nil?
      return false if uri.scheme.to_s.strip.empty?
      return false if uri.host.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.build_form(event_name:, user: nil, email: nil, reset_token: nil, success: nil,
                        request_ip: nil, user_agent: nil, occurred_at_utc: nil)
      occurred_at_utc ||= Time.now.utc.iso8601

      form = {
        "event" => event_name.to_s,
        "occurred_at_utc" => occurred_at_utc.to_s
      }

      if user
        form["user_id"] = user.id.to_s
        form["username"] = user.username.to_s
        form["email"] = user.email.to_s
      elsif email && email.to_s.strip.length > 0
        form["email"] = email.to_s.strip
      end

      # Never send raw token; only sha256
      if reset_token && reset_token.to_s.length > 0
        form["reset_token_sha256"] = Digest::SHA256.hexdigest(reset_token.to_s)
      end

      if success == true
        form["success"] = "1"
      elsif success == false
        form["success"] = "0"
      end

      form["request_ip"] = request_ip.to_s if request_ip && request_ip.to_s.length > 0
      form["user_agent"] = user_agent.to_s if user_agent && user_agent.to_s.length > 0

      sec = SECRET_FIELD.to_s.strip
      form["secret"] = sec if sec.length > 0

      form
    rescue StandardError
      { "event" => event_name.to_s, "occurred_at_utc" => (occurred_at_utc || Time.now.utc.iso8601).to_s }
    end

    # Option B: Use Net::HTTP directly (bypasses FinalDestination SSRF checks)
    def self.post_form_now(form)
      return unless enabled?

      uri = endpoint_uri
      return if uri.nil?

      body = URI.encode_www_form(form)

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.open_timeout = OPEN_TIMEOUT
      http.read_timeout = TIMEOUT_SEC
      http.write_timeout = WRITE_TIMEOUT if http.respond_to?(:write_timeout=)

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Content-Type"] = "application/x-www-form-urlencoded"
      req["User-Agent"] = "Discourse/#{Discourse::VERSION::STRING} #{PLUGIN_NAME}"
      req.body = body

      resp = nil
      http.start { |h| resp = h.request(req) }

      code = (resp&.code.to_i rescue 0)
      dlog("POST OK code=#{code}") if code > 0
      resp
    end

    def self.enqueue(form)
      return unless enabled?
      Jobs.enqueue(:password_reset_webhook_post, form: form)
    rescue => e
      log_warn("enqueue failed: #{e.class}: #{e.message}")
    end
  end

  # ----------------------------
  # Sidekiq Job
  # ----------------------------
  module ::Jobs
    class PasswordResetWebhookPost < ::Jobs::Base
      sidekiq_options retry: 10

      def execute(args)
        form = args["form"] || args[:form]
        unless form.is_a?(Hash)
          Rails.logger.warn("[#{::PasswordResetWebhook::PLUGIN_NAME}] job got invalid form payload")
          return
        end

        ::PasswordResetWebhook.post_form_now(form)
      rescue => e
        Rails.logger.warn("[#{::PasswordResetWebhook::PLUGIN_NAME}] webhook failed in job: #{e.class}: #{e.message}")
        raise # keep retries
      end
    end
  end

  installed = []

  # ============================================================
  # 1) Password reset requested: SessionController#forgot_password
  # ============================================================
  begin
    if defined?(::SessionController) && ::SessionController.method_defined?(:forgot_password)
      module ::PasswordResetWebhook::SessionForgotPasswordPatch
        def forgot_password(*args)
          req = request
          ip = (req&.remote_ip rescue nil)
          ua = (req&.user_agent rescue nil)

          login = nil
          begin
            login = params[:login] || params[:email] || params["login"] || params["email"]
          rescue StandardError
            login = nil
          end

          result = super(*args)

          success = (response.status.to_i >= 200 && response.status.to_i < 300)

          form = ::PasswordResetWebhook.build_form(
            event_name: "password_reset_requested",
            user: nil,
            email: login,
            reset_token: nil,
            success: success,
            request_ip: ip,
            user_agent: ua,
            occurred_at_utc: Time.now.utc.iso8601
          )
          ::PasswordResetWebhook.enqueue(form)

          result
        end
      end

      ::SessionController.prepend(::PasswordResetWebhook::SessionForgotPasswordPatch)
      installed << "SessionController#forgot_password"
    else
      Rails.logger.warn("[discourse-password-reset-webhook] SessionController#forgot_password not found; request hook not installed.")
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch SessionController#forgot_password: #{e.class}: #{e.message}")
  end

  # ============================================================
  # 2) Password reset completed: UsersController (method varies)
  # ============================================================
  begin
    if defined?(::UsersController)
      candidates = [
        :password_reset,
        :password_reset_perform,
        :reset_password,
        :update_password,
        :password_reset_update
      ]

      found = candidates.find { |m| ::UsersController.method_defined?(m) }

      if found
        patch_mod = Module.new do
          define_method(found) do |*args|
            req = request
            ip = (req&.remote_ip rescue nil)
            ua = (req&.user_agent rescue nil)

            token = nil
            begin
              token =
                params[:token] || params[:reset_token] || params[:password_reset_token] ||
                params["token"] || params["reset_token"] || params["password_reset_token"]
            rescue StandardError
              token = nil
            end

            result = super(*args)

            success = (response.status.to_i >= 200 && response.status.to_i < 300)

            form = ::PasswordResetWebhook.build_form(
              event_name: "password_reset_completed",
              user: (current_user rescue nil), # may be nil; OK
              email: nil,
              reset_token: token,
              success: success,
              request_ip: ip,
              user_agent: ua,
              occurred_at_utc: Time.now.utc.iso8601
            )
            ::PasswordResetWebhook.enqueue(form)

            result
          rescue => e
            # best-effort report failure event too
            begin
              form = ::PasswordResetWebhook.build_form(
                event_name: "password_reset_completed",
                user: (current_user rescue nil),
                email: nil,
                reset_token: (params[:token] rescue nil),
                success: false,
                request_ip: (request&.remote_ip rescue nil),
                user_agent: (request&.user_agent rescue nil),
                occurred_at_utc: Time.now.utc.iso8601
              )
              ::PasswordResetWebhook.enqueue(form)
            rescue StandardError
              # ignore
            end
            raise
          end
        end

        ::UsersController.prepend(patch_mod)
        installed << "UsersController##{found}"
      else
        Rails.logger.warn("[discourse-password-reset-webhook] No known UsersController password-reset action found (tried: #{candidates.join(", ")}). Completion hook not installed.")
      end
    else
      Rails.logger.warn("[discourse-password-reset-webhook] UsersController not found; completion hook not installed.")
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch UsersController password-reset action: #{e.class}: #{e.message}")
  end

  if installed.any?
    Rails.logger.warn("[discourse-password-reset-webhook] installed hooks: #{installed.join(" | ")}")
  end
end
