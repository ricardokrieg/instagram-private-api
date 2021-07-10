import { Repository } from '../core/repository';
import {
  AccountRepositoryCurrentUserResponseRootObject,
  AccountRepositoryLoginErrorResponse,
  AccountRepositoryLoginResponseLogged_in_user,
  AccountRepositoryLoginResponseRootObject,
  SpamResponse,
  StatusResponse,
} from '../responses';
import {
  IgLoginBadPasswordError,
  IgLoginInvalidUserError,
  IgLoginTwoFactorRequiredError,
  IgResponseError,
} from '../errors';
import { IgResponse, AccountEditProfileOptions, AccountTwoFactorLoginOptions } from '../types';
import { defaultsDeep, random } from 'lodash';
import { IgSignupBlockError } from '../errors/ig-signup-block.error';
import Bluebird = require('bluebird');
import debug from 'debug';
import * as crypto from 'crypto';
import Chance = require('chance');

export class AccountRepository extends Repository {
  private static accountDebug = debug('ig:account');
  private chance = new Chance();

  public async login(username: string, password: string): Promise<AccountRepositoryLoginResponseLogged_in_user> {
    if (!this.client.state.passwordEncryptionPubKey) {
      await this.client.qe.syncLoginExperiments();
    }
    const { encrypted, time } = this.encryptPassword(password);
    const response = await Bluebird.try(() =>
      this.client.request.send<AccountRepositoryLoginResponseRootObject>({
        method: 'POST',
        url: '/api/v1/accounts/login/',
        form: this.client.request.sign({
          username,
          // password,
          enc_password: `#PWD_INSTAGRAM:4:${time}:${encrypted}`,
          guid: this.client.state.uuid,
          phone_id: this.client.state.phoneId,
          _csrftoken: this.client.state.cookieCsrfToken,
          device_id: this.client.state.deviceId,
          // adid: '' /*this.client.state.adid ? not set on pre-login*/,
          adid: this.client.state.adid,
          google_tokens: '[]',
          login_attempt_count: 0,
          // country_codes: JSON.stringify([{ country_code: '1', source: 'default' }]),
          country_codes: JSON.stringify([{ country_code: '1', sources: ['default'] }]),
          jazoest: AccountRepository.createJazoest(this.client.state.phoneId),
        }),
      }),
    ).catch(IgResponseError, error => {
      if (error.response.body.two_factor_required) {
        AccountRepository.accountDebug(
          `Login failed, two factor auth required: ${JSON.stringify(error.response.body.two_factor_info)}`,
        );
        throw new IgLoginTwoFactorRequiredError(error.response as IgResponse<AccountRepositoryLoginErrorResponse>);
      }
      switch (error.response.body.error_type) {
        case 'bad_password': {
          throw new IgLoginBadPasswordError(error.response as IgResponse<AccountRepositoryLoginErrorResponse>);
        }
        case 'invalid_user': {
          throw new IgLoginInvalidUserError(error.response as IgResponse<AccountRepositoryLoginErrorResponse>);
        }
        default: {
          throw error;
        }
      }
    });
    return response.body.logged_in_user;
  }

  public static createJazoest(input: string): string {
    const buf = Buffer.from(input, 'ascii');
    let sum = 0;
    for (let i = 0; i < buf.byteLength; i++) {
      sum += buf.readUInt8(i);
    }
    return `2${sum}`;
  }

  public encryptPassword(password: string): { time: string; encrypted: string } {
    const randKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const rsaEncrypted = crypto.publicEncrypt(
      {
        key: Buffer.from(this.client.state.passwordEncryptionPubKey, 'base64').toString(),
        // @ts-ignore
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      randKey,
    );
    const cipher = crypto.createCipheriv('aes-256-gcm', randKey, iv);
    const time = Math.floor(Date.now() / 1000).toString();
    cipher.setAAD(Buffer.from(time));
    const aesEncrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
    const sizeBuffer = Buffer.alloc(2, 0);
    sizeBuffer.writeInt16LE(rsaEncrypted.byteLength, 0);
    const authTag = cipher.getAuthTag();
    return {
      time,
      encrypted: Buffer.concat([
        Buffer.from([1, this.client.state.passwordEncryptionKeyId]),
        iv,
        sizeBuffer,
        rsaEncrypted,
        authTag,
        aesEncrypted,
      ]).toString('base64'),
    };
  }

  public async twoFactorLogin(
    options: AccountTwoFactorLoginOptions,
  ): Promise<AccountRepositoryLoginResponseLogged_in_user> {
    options = defaultsDeep(options, {
      trustThisDevice: '1',
      verificationMethod: '1',
    });
    const { body } = await this.client.request.send<AccountRepositoryLoginResponseLogged_in_user>({
      url: '/api/v1/accounts/two_factor_login/',
      method: 'POST',
      form: this.client.request.sign({
        verification_code: options.verificationCode,
        _csrftoken: this.client.state.cookieCsrfToken,
        two_factor_identifier: options.twoFactorIdentifier,
        username: options.username,
        trust_this_device: options.trustThisDevice,
        guid: this.client.state.uuid,
        device_id: this.client.state.deviceId,
        verification_method: options.verificationMethod,
      }),
    });
    return body;
  }

  public async logout() {
    const { body } = await this.client.request.send<StatusResponse>({
      method: 'POST',
      url: '/api/v1/accounts/logout/',
      form: {
        guid: this.client.state.uuid,
        phone_id: this.client.state.phoneId,
        _csrftoken: this.client.state.cookieCsrfToken,
        device_id: this.client.state.deviceId,
        _uuid: this.client.state.uuid,
      },
    });
    return body;
  }

  async create({ force_sign_up_code, password, email, username, first_name, day, month, year }) {
    const { encrypted, time } = this.encryptPassword(password);

    const { body } = await Bluebird.try(() =>
      this.client.request.send({
        method: 'POST',
        url: '/api/v1/accounts/create/',
        form: this.client.request.sign({
          is_secondary_account_creation: 'false',
          jazoest: AccountRepository.createJazoest(this.client.state.phoneId),
          tos_version: 'row',
          suggestedUsername: '',
          sn_result: 'API_ERROR: class X.7ed:7: ',
          do_not_auto_login_if_credentials_match: 'true',
          phone_id: this.client.state.phoneId,
          enc_password: `#PWD_INSTAGRAM:4:${time}:${encrypted}`,
          _csrftoken: this.client.state.cookieCsrfToken,
          username,
          first_name,
          day,
          adid: this.client.state.adid,
          guid: this.client.state.uuid,
          year,
          device_id: this.client.state.deviceId,
          _uuid: this.client.state.uuid,
          email,
          month,
          sn_nonce: this.getSnNonce({ id: email }),
          force_sign_up_code,
          waterfall_id: this.client.state.waterfallId,
          qs_stamp: '',
          has_sms_consent: 'true',
          one_tap_opt_in: 'true',
        }),
      }),
    ).catch(IgResponseError, error => {
      switch (error.response.body.error_type) {
        case 'signup_block': {
          AccountRepository.accountDebug('Signup failed');
          throw new IgSignupBlockError(error.response as IgResponse<SpamResponse>);
        }
        default: {
          throw error;
        }
      }
    });
    return body;
  }

  async createWithPhoneNumber({ username, password, first_name, day, month, year, input_phone_number, input_code }) {
    const phone_number = await input_phone_number();

    const { body } = await Bluebird.try(async () => {
      try {
        await this.checkPhoneNumber({ phone_number });
      } catch {
        AccountRepository.accountDebug(`Check phone number ${phone_number} failed`);
      }

      await this.sendSignupSmsCode({ phone_number });

      const verification_code = await input_code({ phone_number });
      await this.validateSignupSmsCode({ verification_code, phone_number });

      await this.fetchSIHeaders();

      await this.usernameSuggestions({ name: first_name, email: '' });
      await this.client.consent.checkAgeEligibility({ day, month, year });
      await this.client.consent.newUserFlowBegins();
      await this.dynamicOnboardingGetSteps();

      const usernameStatus = await this.client.user.checkUsername({ username });
      if (!usernameStatus['available']) {
        throw new Error(usernameStatus['error']);
      }

      return await this.createValidated({
        verification_code,
        password,
        phone_number,
        username,
        first_name,
        day,
        month,
        year,
      });
    }).catch(IgResponseError, error => {
      switch (error.response.body.error_type) {
        case 'signup_block': {
          AccountRepository.accountDebug('Signup failed');
          throw new IgSignupBlockError(error.response as IgResponse<SpamResponse>);
        }
        default: {
          throw error;
        }
      }
    });
    return body;
  }

  async createWithEmail({ username, password, first_name, day, month, year, input_email, input_code }) {
    const email = await input_email();

    const { body } = await Bluebird.try(async () => {
      // try {
      //   await this.checkEmail({ email });
      // } catch {
      //   AccountRepository.accountDebug(`Check email ${email} failed`);
      // }

      await this.sendVerifyEmail({ email });

      const verification_code = await input_code({ email });
      const confirmationResponse = await this.checkConfirmationCode({ verification_code, email });

      const force_sign_up_code = confirmationResponse['signup_code'];

      await this.fetchSIHeaders();

      await this.usernameSuggestions({ name: first_name, email });
      await this.client.consent.checkAgeEligibility({ day, month, year });
      await this.client.consent.newUserFlowBegins();
      await this.dynamicOnboardingGetSteps();

      const usernameStatus = await this.client.user.checkUsername({ username });
      if (!usernameStatus['available']) {
        throw new Error(usernameStatus['error']);
      }

      return await this.create({
        force_sign_up_code,
        password,
        email,
        username,
        first_name,
        day,
        month,
        year,
      });
    }).catch(IgResponseError, error => {
      switch (error.response.body.error_type) {
        case 'signup_block': {
          AccountRepository.accountDebug('Signup failed');
          throw new IgSignupBlockError(error.response as IgResponse<SpamResponse>);
        }
        default: {
          throw error;
        }
      }
    });
    return body;
  }

  public async currentUser() {
    const { body } = await this.client.request.send<AccountRepositoryCurrentUserResponseRootObject>({
      url: '/api/v1/accounts/current_user/',
      qs: {
        edit: true,
      },
    });
    return body.user;
  }

  public async setBiography(text: string) {
    const { body } = await this.client.request.send<AccountRepositoryCurrentUserResponseRootObject>({
      url: '/api/v1/accounts/set_biography/',
      method: 'POST',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        device_id: this.client.state.deviceId,
        _uuid: this.client.state.uuid,
        raw_text: text,
      }),
    });
    return body.user;
  }

  public async changeProfilePicture(picture: Buffer): Promise<AccountRepositoryCurrentUserResponseRootObject> {
    const uploadId = Date.now().toString();
    await this.client.upload.photo({
      file: picture,
      uploadId,
    });
    const { body } = await this.client.request.send<AccountRepositoryCurrentUserResponseRootObject>({
      url: '/api/v1/accounts/change_profile_picture/',
      method: 'POST',
      form: {
        _csrftoken: this.client.state.cookieCsrfToken,
        _uuid: this.client.state.uuid,
        use_fbuploader: true,
        upload_id: uploadId,
      },
    });
    return body;
  }

  public async changeProfilePictureAndFirstPost(
    picture: Buffer,
  ): Promise<AccountRepositoryCurrentUserResponseRootObject> {
    const uploadId = Date.now().toString();
    const name = `${uploadId}_0_${random(1000000000, 9999999999)}`;
    const waterfallId = this.chance.guid();

    const { offset } = await this.client.upload.initPhoto({ uploadId, name, waterfallId });
    await this.client.upload.photo({ file: picture, uploadId, name, offset, waterfallId });

    const { body } = await this.client.request.send<AccountRepositoryCurrentUserResponseRootObject>({
      url: '/api/v1/accounts/change_profile_picture/',
      method: 'POST',
      form: {
        _csrftoken: this.client.state.cookieCsrfToken,
        _uuid: this.client.state.uuid,
        use_fbuploader: true,
        share_to_feed: true,
        upload_id: uploadId,
      },
    });
    return body;
  }

  public async editProfile(options: AccountEditProfileOptions) {
    const { body } = await this.client.request.send<AccountRepositoryCurrentUserResponseRootObject>({
      url: '/api/v1/accounts/edit_profile/',
      method: 'POST',
      form: this.client.request.sign({
        ...options,
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        device_id: this.client.state.deviceId,
        _uuid: this.client.state.uuid,
      }),
    });
    return body.user;
  }

  public async changePassword(oldPassword: string, newPassword: string) {
    const { body } = await this.client.request.send({
      url: '/api/v1/accounts/change_password/',
      method: 'POST',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        _uuid: this.client.state.uuid,
        old_password: oldPassword,
        new_password1: newPassword,
        new_password2: newPassword,
      }),
    });
    return body;
  }

  public async removeProfilePicture() {
    return this.command('remove_profile_picture');
  }

  public async setPrivate() {
    return this.command('set_private');
  }

  public async setPublic() {
    return this.command('set_public');
  }

  private async command(command: string): Promise<AccountRepositoryCurrentUserResponseRootObject> {
    const { body } = await this.client.request.send<AccountRepositoryCurrentUserResponseRootObject>({
      url: `/api/v1/accounts/${command}/`,
      method: 'POST',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        _uuid: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async readMsisdnHeader(usage = 'default') {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/read_msisdn_header/',
      headers: {
        'X-Device-Id': this.client.state.uuid,
      },
      form: this.client.request.sign({
        mobile_subno_usage: usage,
        device_id: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async msisdnHeaderBootstrap(usage = 'default') {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/msisdn_header_bootstrap/',
      form: this.client.request.sign({
        mobile_subno_usage: usage,
        device_id: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async contactPointPrefill(usage = 'default') {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/contact_point_prefill/',
      form: this.client.request.sign({
        mobile_subno_usage: usage,
        device_id: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async contactPointPrefillV2(usage = 'default') {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/contact_point_prefill/',
      form: this.client.request.sign({
        phone_id: this.client.state.phoneId,
        _csrftoken: this.client.state.cookieCsrfToken,
        usage,
      }),
    });
    return body;
  }

  public async contactPointPrefillAutoConfirmationV2() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/contact_point_prefill/',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        device_id: this.client.state.uuid,
        _uuid: this.client.state.uuid,
        phone_id: this.client.state.phoneId,
        usage: 'auto_confirmation',
      }),
    });
    return body;
  }

  public async getPrefillCandidates() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/get_prefill_candidates/',
      form: this.client.request.sign({
        android_device_id: this.client.state.deviceId,
        usages: '["account_recovery_omnibox"]',
        device_id: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async getPrefillCandidatesV2() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/get_prefill_candidates/',
      form: this.client.request.sign({
        android_device_id: this.client.state.deviceId,
        phone_id: this.client.state.phoneId,
        usages: '["account_recovery_omnibox"]',
        device_id: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async processContactPointSignals() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/process_contact_point_signals/',
      form: this.client.request.sign({
        phone_id: this.client.state.phoneId,
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        device_id: this.client.state.uuid,
        _uuid: this.client.state.uuid,
        google_tokens: '[]',
      }),
    });
    return body;
  }

  public async sendRecoveryFlowEmail(query: string) {
    const { body } = await this.client.request.send({
      url: '/api/v1/accounts/send_recovery_flow_email/',
      method: 'POST',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        adid: '' /*this.client.state.adid ? not available on pre-login?*/,
        guid: this.client.state.uuid,
        device_id: this.client.state.deviceId,
        query,
      }),
    });
    return body;
  }

  async checkPhoneNumber({ phone_number }) {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/check_phone_number/',
      form: this.client.request.sign({
        phone_id: this.client.state.phoneId,
        login_nonce_map: '{}',
        phone_number,
        _csrftoken: this.client.state.cookieCsrfToken,
        guid: this.client.state.uuid,
        device_id: this.client.state.deviceId,
        prefill_shown: 'False',
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async sendSignupSmsCode({ phone_number }) {
    const phoneNumberStripped = phone_number.replace(/[^\+0-9]/g, '');

    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/send_signup_sms_code/',
      form: this.client.request.sign({
        phone_id: this.client.state.phoneId,
        phone_number: phoneNumberStripped,
        _csrftoken: this.client.state.cookieCsrfToken,
        guid: this.client.state.uuid,
        device_id: this.client.state.deviceId,
        android_build_type: 'release',
        waterfall_id: this.client.state.waterfallId,
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async validateSignupSmsCode({ verification_code, phone_number }) {
    const phoneNumberStripped = phone_number.replace(/[^\+0-9]/g, '');

    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/validate_signup_sms_code/',
      form: this.client.request.sign({
        verification_code,
        phone_number: phoneNumberStripped,
        _csrftoken: this.client.state.cookieCsrfToken,
        guid: this.client.state.uuid,
        device_id: this.client.state.deviceId,
        waterfall_id: this.client.state.waterfallId,
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async checkEmail({ email }) {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/check_email/',
      form: this.client.request.sign({
        android_device_id: this.client.state.deviceId,
        login_nonce_map: '{}',
        _csrftoken: this.client.state.cookieCsrfToken,
        login_nonces: '[]',
        email,
        qe_id: this.client.state.uuid,
        waterfall_id: this.client.state.waterfallId,
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async sendVerifyEmail({ email }) {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/send_verify_email/',
      form: this.client.request.sign({
        phone_id: this.client.state.phoneId,
        _csrftoken: this.client.state.cookieCsrfToken,
        guid: this.client.state.uuid,
        device_id: this.client.state.deviceId,
        email,
        waterfall_id: this.client.state.waterfallId,
        auto_confirm_only: 'false',
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async checkConfirmationCode({ verification_code, email }) {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/check_confirmation_code/',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        code: verification_code,
        device_id: this.client.state.deviceId,
        email,
        waterfall_id: this.client.state.waterfallId,
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async fetchSIHeaders() {
    const guid = this.client.state.uuid.replace(/\-/g, '');

    const { body } = await this.client.request.send({
      method: 'GET',
      url: `/api/v1/si/fetch_headers/?guid=${guid}&challenge_type=signup`,
    });
    return body;
  }

  async currentAED() {
    const { body } = await this.client.request.send({
      method: 'GET',
      url: '/api/v1/aed/current/',
    });
    return body;
  }

  async multipleAccountsGetAccountFamily() {
    const { body } = await this.client.request.send({
      method: 'GET',
      url: '/api/v1/multiple_accounts/get_account_family/',
    });
    return body;
  }

  async nuxNewAccountNuxSeen() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/nux/new_account_nux_seen/',
      form: this.client.request.sign({
        is_fb4a_installed: 'false', // TODO confirm if should be false or 'false'
        phone_id: this.client.state.phoneId,
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        guid: this.client.state.uuid,
        _uuid: this.client.state.uuid,
        waterfall_id: this.client.state.waterfallId,
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async usernameSuggestions({ name, email }) {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/username_suggestions/',
      form: this.client.request.sign({
        phone_id: this.client.state.phoneId,
        _csrftoken: this.client.state.cookieCsrfToken,
        guid: this.client.state.uuid,
        name,
        device_id: this.client.state.deviceId,
        email,
        waterfall_id: this.client.state.waterfallId,
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async dynamicOnboardingGetSteps() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/dynamic_onboarding/get_steps/',
      form: this.client.request.sign({
        is_secondary_account_creation: 'false',
        fb_connected: 'false',
        seen_steps: '[]',
        progress_state: 'prefetch',
        phone_id: this.client.state.phoneId,
        fb_installed: 'false',
        locale: this.client.state.language,
        timezone_offset: this.client.state.timezoneOffset,
        _csrftoken: this.client.state.cookieCsrfToken,
        network_type: 'WIFI-UNKNOWN',
        guid: this.client.state.uuid,
        is_ci: 'false',
        android_id: this.client.state.deviceId,
        waterfall_id: this.client.state.waterfallId,
        reg_flow_taken: 'phone',
        tos_accepted: 'false',
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async dynamicOnboardingGetStepsStart() {
    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/dynamic_onboarding/get_steps/',
      form: this.client.request.sign({
        is_secondary_account_creation: 'false',
        fb_connected: 'false',
        seen_steps: '[]',
        progress_state: 'start',
        phone_id: this.client.state.phoneId,
        fb_installed: 'false',
        locale: this.client.state.language,
        timezone_offset: this.client.state.timezoneOffset,
        _csrftoken: this.client.state.cookieCsrfToken,
        network_type: 'WIFI-UNKNOWN',
        _uid: this.client.state.cookieUserId,
        guid: this.client.state.uuid,
        _uuid: this.client.state.uuid,
        is_ci: 'false',
        android_id: this.client.state.deviceId,
        waterfall_id: this.client.state.waterfallId,
        reg_flow_taken: 'phone',
        tos_accepted: 'true',
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  async createValidated({ verification_code, password, phone_number, username, first_name, day, month, year }) {
    const { encrypted, time } = this.encryptPassword(password);
    const phoneNumberStripped = phone_number.replace(/[^\+0-9]/g, '');

    const { body } = await this.client.request.send({
      method: 'POST',
      url: '/api/v1/accounts/create_validated/',
      form: this.client.request.sign({
        is_secondary_account_creation: 'false',
        jazoest: AccountRepository.createJazoest(this.client.state.phoneId),
        tos_version: 'row',
        suggestedUsername: '',
        verification_code,
        sn_result: 'API_ERROR: class X.7:7: ',
        do_not_auto_login_if_credentials_match: 'true',
        phone_id: this.client.state.phoneId,
        enc_password: `#PWD_INSTAGRAM:4:${time}:${encrypted}`,
        phone_number: phoneNumberStripped,
        _csrftoken: this.client.state.cookieCsrfToken,
        username,
        first_name,
        day,
        adid: this.client.state.adid,
        guid: this.client.state.uuid,
        year,
        device_id: this.client.state.deviceId,
        _uuid: this.client.state.uuid,
        month,
        sn_nonce: this.getSnNonce({ id: phoneNumberStripped }),
        force_sign_up_code: '',
        waterfall_id: this.client.state.waterfallId,
        qs_stamp: '',
        has_sms_consent: 'true',
        one_tap_opt_in: 'true',
      }),
    });
    AccountRepository.accountDebug(body);
    return body;
  }

  getSnNonce({ id }) {
    const timestamp = Math.floor(new Date().getTime() / 1000);
    const random = crypto.randomBytes(12);
    const str = `${id}|${timestamp}|${random.toString()}`;

    return Buffer.from(str).toString('base64');
  }
}
