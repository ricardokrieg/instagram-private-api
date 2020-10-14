import { Repository } from '../core/repository';
import Chance = require('chance');
import Bluebird = require('bluebird');
import debug from 'debug';

export class ConsentRepository extends Repository {
  private static consentDebug = debug('ig:consent');

  public async auto() {
    const response = await this.existingUserFlow();
    if (response.screen_key === 'already_finished') {
      return response;
    }
    const dob = new Chance().birthday();
    await Bluebird.try(() => this.existingUserFlowIntro()).catch(() => {});
    await Bluebird.try(() => this.existingUserFlowTosAndTwoAgeButton()).catch(() => {});
    await Bluebird.try(() => this.existingUserFlowDob(dob.getFullYear(), dob.getMonth(), dob.getDay())).catch(() => {});
    return true;
  }

  public existingUserFlowIntro() {
    return this.existingUserFlow({
      current_screen_key: 'qp_intro',
      updates: JSON.stringify({ existing_user_intro_state: '2' }),
    });
  }

  public existingUserFlowDob(year: string | number, month: string | number, day: string | number) {
    return this.existingUserFlow({
      current_screen_key: 'dob',
      day: String(day),
      month: String(month),
      year: String(year),
    });
  }

  public existingUserFlowTosAndTwoAgeButton() {
    return this.existingUserFlow({
      current_screen_key: 'tos_and_two_age_button',
      updates: JSON.stringify({ age_consent_state: '2', tos_data_policy_consent_state: '2' }),
    });
  }

  public async existingUserFlow(data?: { [x: string]: any }) {
    const { body } = await this.client.request.send({
      url: '/api/v1/consent/existing_user_flow/',
      method: 'POST',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        _uid: this.client.state.cookieUserId,
        _uuid: this.client.state.uuid,
        ...data,
      }),
    });
    return body;
  }

  public async newUserFlowBegins() {
    const { body } = await this.client.request.send({
      url: '/api/v1/consent/new_user_flow_begins/',
      method: 'POST',
      form: this.client.request.sign({
        _csrftoken: this.client.state.cookieCsrfToken,
        device_id: this.client.state.uuid,
      }),
    });
    return body;
  }

  public async checkAgeEligibility({ day, month, year }) {
    const { body } = await this.client.request.send({
      url: '/api/v1/consent/check_age_eligibility/',
      method: 'POST',
      form: {
        _csrftoken: this.client.state.cookieCsrfToken,
        day,
        year,
        month,
      },
    });
    ConsentRepository.consentDebug(body);
    return body;
  }
}
