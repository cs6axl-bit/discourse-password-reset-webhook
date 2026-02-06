# frozen_string_literal: true

# name: discourse-password-reset-webhook
# about: Posts a JSON webhook to a PHP endpoint when password reset is requested and when it is completed.
# version: 1.0.0
# authors: you

enabled_site_setting :password_reset_webhook_enabled

after_initialize do
  module ::PasswordResetWebhook
    PLUGIN_NAME = "discourse-password-reset-webhook"

    def self.log_prefix
      "[#{PLUGIN_NAME}]"
    end

    def self.endpoint_url
      SiteSetting.password_reset_webhook_endpoint_url.to_s.strip
    end

    def self.enabled?
      SiteSetting.password_reset_webhook_enabled &&
        endpoint_url.length > 0
    end

    def self.http_timeout
      SiteSetting.password_reset_webhook_timeout_seconds.to_i
    end

    def self.open_timeout
      SiteSetting.password_reset_webhook_open_timeout_seconds.to_i
    end

    def self.post(event_name:, user: nil, reset_token: nil, request_ip: nil, extra: {})
      return unless enabled?

      payload = {
        event: event_name, # "password_reset_requested" | "password_reset_completed"
        ts: Time.now.utc.iso8601,
        discourse_base_url: Discourse.base_url,
        user: user ? {
          id: user.id,
          username: user.username,
          email: user.email
        } : nil,
        reset: {
          token_present: !!reset_token,
          token_sha256: reset_token ? Digest::SHA256.hexdigest(reset_token) : nil
        },
        request: {
          ip: request_ip
        },
        extra: extra
      }

      begin
        FinalDestination::HTTP.post(
          endpoint_url,
          body: payload.to_json,
          headers: { "Content-Type" => "application/json" },
          timeout: http_timeout,
          open_timeout: open_timeout
        )
      rescue => e
        Rails.logger.warn("#{log_prefix} webhook failed: #{e.class}: #{e.message}")
      end
    end
  end

  # -----------------------------
  # 1) Password reset requested
  # -----------------------------
  #
  # Discourse uses a token email flow; we hook the method that generates/sends it.
  # This catches the real "request" event (not just viewing the form).
  #
  begin
    ::EmailToken.class_eval do
      class << self
        alias_method :_prw_original_send_password_reset_email, :send_password_reset_email
      end

      def self.send_password_reset_email(user, opts = {})
        result = _prw_original_send_password_reset_email(user, opts)

        # Best-effort IP extraction (may be nil depending on call path)
        ip = nil
        begin
          ip = opts[:request_ip] if opts.is_a?(Hash)
        rescue
          # ignore
        end

        # The reset token is not always directly available here; keep "token_present" false if nil.
        ::PasswordResetWebhook.post(
          event_name: "password_reset_requested",
          user: user,
          reset_token: nil,
          request_ip: ip,
          extra: {
            username_or_email_submitted: opts.is_a?(Hash) ? (opts[:username_or_email] || nil) : nil
          }
        )

        result
      rescue => e
        Rails.logger.warn("[discourse-password-reset-webhook] request hook error: #{e.class}: #{e.message}")
        # still return original result if we got it
        result
      end
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch EmailToken.send_password_reset_email: #{e.class}: #{e.message}")
  end

  # -----------------------------
  # 2) Password reset completed
  # -----------------------------
  #
  # After the user sets a new password, the reset token is "consumed".
  # We hook the PasswordReset flow to post a completion event.
  #
  begin
    if defined?(::PasswordReset)
      ::PasswordReset.class_eval do
        alias_method :_prw_original_perform!, :perform!

        def perform!
          # Capture a few details before the token is consumed
          user = self.user rescue nil
          token = self.token rescue nil

          result = _prw_original_perform!

          ::PasswordResetWebhook.post(
            event_name: "password_reset_completed",
            user: user,
            reset_token: token,
            request_ip: (self.respond_to?(:ip_address) ? (self.ip_address rescue nil) : nil),
            extra: {
              success: true
            }
          )

          result
        rescue => e
          # If perform! raises, do NOT claim completion; send a failure extra (optional)
          begin
            ::PasswordResetWebhook.post(
              event_name: "password_reset_completed",
              user: (self.user rescue nil),
              reset_token: (self.token rescue nil),
              request_ip: (self.respond_to?(:ip_address) ? (self.ip_address rescue nil) : nil),
              extra: {
                success: false,
                error_class: e.class.to_s
              }
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
