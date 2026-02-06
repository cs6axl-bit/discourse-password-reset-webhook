# frozen_string_literal: true

# name: discourse-password-reset-webhook
# about: Sends form-urlencoded webhook to PHP endpoint when password reset is requested and when it is completed (async via Sidekiq).
# version: 1.3.0
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
    ENABLED       = true
    # =========================

    def self.enabled?
      ENABLED && ENDPOINT_URL.to_s.strip.length > 0
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
    end

    def self.post_form_now(form)
      return unless enabled?

      body = URI.encode_www_form(form)

      FinalDestination::HTTP.post(
        ENDPOINT_URL,
        body: body,
        headers: { "Content-Type" => "application/x-www-form-urlencoded" },
        timeout: TIMEOUT_SEC,
        open_timeout: OPEN_TIMEOUT
      )
    end

    def self.enqueue(form)
      return unless enabled?

      Jobs.enqueue(:password_reset_webhook_post, form: form)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] enqueue failed: #{e.class}: #{e.message}")
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

  # ------------------------------------------------------------
  # Hook: password reset requested (UsersController#forgot_password)
  # ------------------------------------------------------------
  begin
    if defined?(::UsersController)
      ::UsersController.class_eval do
        alias_method :_prw_original_forgot_password, :forgot_password

        def forgot_password
          req = request
          ip = (req&.remote_ip rescue nil)
          ua = (req&.user_agent rescue nil)

          email = nil
          begin
            email = params[:login] || params[:email] || params["login"] || params["email"]
          rescue
            email = nil
          end

          result = _prw_original_forgot_password

          # If controller returned a 2xx we treat as success; otherwise failure
          success = (response.status.to_i >= 200 && response.status.to_i < 300)

          form = ::PasswordResetWebhook.build_form(
            event_name: "password_reset_requested",
            user: (current_user rescue nil), # usually nil for forgot_password; fine
            email: email,
            reset_token: nil,
            success: success,
            request_ip: ip,
            user_agent: ua,
            occurred_at_utc: Time.now.utc.iso8601
          )
          ::PasswordResetWebhook.enqueue(form)

          result
        rescue => e
          Rails.logger.warn("[discourse-password-reset-webhook] forgot_password hook error: #{e.class}: #{e.message}")
          raise
        end
      end
    else
      Rails.logger.warn("[discourse-password-reset-webhook] UsersController not found; request hook not installed.")
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch UsersController#forgot_password: #{e.class}: #{e.message}")
  end

  # ------------------------------------------------------------
  # Hook: password reset completed (UsersController#password_reset)
  # ------------------------------------------------------------
  begin
    if defined?(::UsersController) && ::UsersController.method_defined?(:password_reset)
      ::UsersController.class_eval do
        alias_method :_prw_original_password_reset, :password_reset

        def password_reset
          req = request
          ip = (req&.remote_ip rescue nil)
          ua = (req&.user_agent rescue nil)

          # token param name varies; cover common ones
          token = nil
          begin
            token =
              params[:token] || params[:reset_token] || params[:password_reset_token] ||
              params["token"] || params["reset_token"] || params["password_reset_token"]
          rescue
            token = nil
          end

          result = _prw_original_password_reset

          success = (response.status.to_i >= 200 && response.status.to_i < 300)

          user = nil
          begin
            # if a user is logged in at this moment use it; otherwise best-effort lookup via token is not safe here
            user = (current_user rescue nil)
          rescue
            user = nil
          end

          form = ::PasswordResetWebhook.build_form(
            event_name: "password_reset_completed",
            user: user,
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
          # Try to also send failure event
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
          rescue
            # ignore
          end
          raise
        end
      end
    else
      Rails.logger.warn("[discourse-password-reset-webhook] UsersController#password_reset not found; completion hook not installed.")
    end
  rescue => e
    Rails.logger.warn("[discourse-password-reset-webhook] failed to patch UsersController#password_reset: #{e.class}: #{e.message}")
  end
end
