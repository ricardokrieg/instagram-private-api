import { shuffle } from 'lodash';
import { Repository } from '../core/repository';
import Bluebird = require('bluebird');

export class SimulateService extends Repository {
  private get preLoginFlowRequests(): Array<() => any> {
    return [
      () => this.client.account.readMsisdnHeader(),
      () => this.client.account.msisdnHeaderBootstrap('ig_select_app'),
      () => this.client.zr.tokenResult(),
      () => this.client.account.contactPointPrefill('prefill'),
      () => this.client.launcher.preLoginSync(),
      () => this.client.qe.syncLoginExperiments(),
      () => this.client.attribution.logAttribution(),
      () => this.client.account.getPrefillCandidates(),
    ];
  }

  private get preLoginFlowRequestsV2(): Array<() => any> {
    return [
      () => this.client.account.contactPointPrefillV2('prefill'),
      () => this.client.launcher.preLoginSyncV2(),
      () => this.client.qe.syncLoginExperimentsV2(),
      () => this.client.account.getPrefillCandidatesV2(),
    ];
  }

  private get postLoginFlowRequests(): Array<() => any> {
    return [
      () => this.client.zr.tokenResult(),
      () => this.client.launcher.postLoginSync(),
      () => this.client.qe.syncExperiments(),
      () => this.client.attribution.logAttribution(),
      () => this.client.attribution.logResurrectAttribution(),
      () => this.client.loom.fetchConfig(),
      () => this.client.linkedAccount.getLinkageStatus(),
      // () => this.client.creatives.writeSupportedCapabilities(),
      // () => this.client.account.processContactPointSignals(),
      () => this.client.feed.timeline().request({ recoveredFromCrash: '1', reason: 'cold_start_fetch' }),
      () => this.client.fbsearch.suggestedSearches('users'),
      () => this.client.fbsearch.suggestedSearches('blended'),
      () => this.client.fbsearch.recentSearches(),
      () => this.client.direct.rankedRecipients('reshare'),
      () => this.client.direct.rankedRecipients('raven'),
      () => this.client.direct.getPresence(),
      () => this.client.feed.directInbox().request(),
      () => this.client.media.blocked(),
      () => this.client.qp.batchFetch(),
      () => this.client.qp.getCooldowns(),
      () => this.client.user.arlinkDownloadInfo(),
      () => this.client.discover.topicalExplore(),
      () => this.client.discover.markSuSeen(),
      () => this.facebookOta(),
      () => this.client.status.getViewableStatuses(),
    ];
  }

  private get postSignupFlowRequestsV2(): Array<() => any> {
    return [
      () => this.client.account.multipleAccountsGetAccountFamily(),
      () => this.client.account.nuxNewAccountNuxSeen(),
      () => this.client.launcher.postSignupSyncV2(),
      () => this.client.qe.syncSignupExperimentsV2(),
      () => this.client.zr.tokenResult(),
      () => this.client.account.dynamicOnboardingGetStepsStart(),
      () => this.client.account.contactPointPrefillAutoConfirmationV2(),
      () => this.client.qe.syncSignupExperimentsV2(),
      () => this.client.qe.syncSignupExperimentsV2(),
    ];
  }

  private static async executeRequestsFlow({
    requests,
    concurrency = 1,
    toShuffle = true,
  }: {
    requests: Array<() => any>;
    concurrency?: number;
    toShuffle?: boolean;
  }) {
    if (toShuffle) {
      requests = shuffle(requests);
    }
    await Bluebird.map(requests, request => request(), { concurrency });
  }

  public async preLoginFlow(concurrency?: number, toShuffle?: boolean) {
    return SimulateService.executeRequestsFlow({
      requests: this.preLoginFlowRequestsV2,
      concurrency,
      toShuffle,
    });
  }

  public async postLoginFlow(concurrency?: number, toShuffle?: boolean) {
    return SimulateService.executeRequestsFlow({
      requests: this.postLoginFlowRequests,
      concurrency,
      toShuffle,
    });
  }

  public async postSignupFlow(concurrency?: number, toShuffle?: boolean) {
    return SimulateService.executeRequestsFlow({
      requests: this.postSignupFlowRequestsV2,
      concurrency,
      toShuffle,
    });
  }

  private async facebookOta() {
    const uid = this.client.state.cookieUserId;
    const { body } = await this.client.request.send({
      url: '/api/v1/facebook_ota/',
      qs: {
        fields: this.client.state.fbOtaFields,
        custom_user_id: uid,
        signed_body: this.client.request.signature('') + '.',
        ig_sig_key_version: this.client.state.signatureVersion,
        version_code: this.client.state.appVersionCode,
        version_name: this.client.state.appVersion,
        custom_app_id: this.client.state.fbOrcaApplicationId,
        custom_device_id: this.client.state.uuid,
      },
    });
    return body;
  }
}
