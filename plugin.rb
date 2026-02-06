# frozen_string_literal: true

# name: discourse-password-reset-webhook
# about: Sends form-urlencoded webhook to PHP endpoint when password reset is requested and when it is completed.
# version: 1.1.1
# authors: you

after_initialize do
  module ::PasswordResetWebhook
    PLUGIN_NAME = "discourse-password-reset-webhook"

    # =========================
    # CONFIG (EDIT THESE)
    # =========================
    ENDPOINT_URL  = "http://172.17.0.1:8081/password_reset_update.php"
    SECRET_FIELD  = ""  # optional; sent as form field "secret" if not blank
    TIMEOUT_SEC   = 3
    OPEN_TIMEOUT  = 2

    # Set false to disable quickly without uninstalling plugin
    ENABLED       = true

    # =========================

    def self.enabled?
      ENABLED && ENDPOINT_URL.to_s.strip.length > 0
    end

    def self.post_form(event_name:, user: nil, reset_token: nil, success: nil, request_ip: nil, user_agent: nil, occurred_at_utc: nil)
      return unless enabled?

      occurred_at_utc ||= Time.now.utc.iso8601

      form = {
        "event" => event_name.to_s,
        "occurred_at_utc" => occurred_at_utc.to_s
      }

      if user
        form["user_id"] = user.id.to_s
        form["username"] = user.username.to_s
        form["email"] = user.email.to_s
      end

      # Never send raw token; only sha256 (matches your PHP column)
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

      body = URI.encode_www_form(form)

      FinalDestination::HTTP.post(
        ENDPOINT_URL,
        body: body,
        headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        timeout: TIMEOUT_SEC,
        open_timeout: OPEN_TIMEOUT
      )
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] webhook failed: #{e.class}: #{e.message}")
    end
  end

  # ------------------------------------------------------------
  # 1) Password reset requested
  # ------------------------------------------------------------
  begin
    ::EmailToken.class_eval do
      class << self
        alias_method :_prw_original_send_password_reset_email, :send_password_reset_email
      end

      def self.send_password_reset_email(user, opts = {})
        result = _prw_original_send_password_reset_email(user, opts)

        ip = nil
        ua = nil
        begin
          if opts.is_a?(Hash)
            ip = opts[:request_ip] || opts["request_ip"]
            ua = opts[:user_agent] || opts["user_agent"]
          end
        rescue
          ip = nil
          ua = nil
        end

        ::PasswordResetWebhook.post_form(
          event_name: "password_reset_requested",
          user: user,
          reset_token: nil,
          success: nil,
          request_ip: ip,
          user_agent: ua,
          occurred_at_utc: Time.now.utc.iso8601
        )

        result
      rescue => e
        Rails.logger.warn("[discourse-password-reset-webhook] request hook error: #{e.class}: #{e.message}")
        result
      end
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch EmailToken.send_password_reset_email: #{e.class}: #{e.message}")
  end

  # ------------------------------------------------------------
  # 2) Password reset completed
  # ------------------------------------------------------------
  begin
    if defined?(::PasswordReset)
      ::PasswordReset.class_eval do
        alias_method :_prw_original_perform!, :perform!

        def perform!
          user = (self.user rescue nil)
          token = (self.token rescue nil)

          ip = nil
          begin
            ip = (self.respond_to?(:ip_address) ? (self.ip_address rescue nil) : nil)
          rescue
            ip = nil
          end

          result = _prw_original_perform!

          ::PasswordResetWebhook.post_form(
            event_name: "password_reset_completed",
            user: user,
            reset_token: token,
            success: true,
            request_ip: ip,
            user_agent: nil,
            occurred_at_utc: Time.now.utc.iso8601
          )

          result
        rescue => e
          # report failure too (optional, but useful)
          begin
            ::PasswordResetWebhook.post_form(
              event_name: "password_reset_completed",
              user: (self.user rescue nil),
              reset_token: (self.token rescue nil),
              success: false,
              request_ip: (self.respond_to?(:ip_address) ? (self.ip_address rescue nil) : nil),
              user_agent: nil,
              occurred_at_utc: Time.now.utc.iso8601
            )
          rescue
            # ignore
          end
          raise
        end
      end
    else
      Rails.logger.warn("[discourse-password-reset-webhook] PasswordReset class not found; completion hook not installed.")
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch PasswordReset.perform!: #{e.class}: #{e.message}")
  end
end
