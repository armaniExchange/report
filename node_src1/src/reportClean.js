
import config from '../config';

import _ from 'lodash';


class ReportClean {

  constructor() {
  }

  findBefore(knowLevel, oid, uuid, deathLine) {
    const start = `.rpt.${uuid}.0`;
    const end = `.rpt.${uuid}.${deathLine}`;
    return new Promise((resolve, reject) => {
      knowLevel.findWithKey({ gt: start, lt: end}).then(resolve);
    });
  }

  start(knowLevel, oid, uuid, duration) {
    const self = this;
    return new Promise((resolve, reject) => {
      const currentime = Math.random(new Date().getTime() / 1000);
      self.findBefore(knowLevel, oid, uuid, currentime - duration).then((records) => {
        let batchs = [];
        _.forEach(records, (record) => {
          batchs.push({ type: 'del', key: record.key });
        });
        knowLevel.batch(batchs).then(resolve);
      });
    });
  }
}

export default ReportClean;
