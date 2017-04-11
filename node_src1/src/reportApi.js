
import KnowLevel from './knowLevel';
import SchemaMapping from './schemaMapping';

import config from '../config';
import filters from '../algorithm/filter';
import * as utils from './utils';
import _ from 'lodash';

class ReportApi {

  constructor() {
    this.knowLevels = {};
    this.initKnowLevel();
    this.mapping = new SchemaMapping();
  }

  initKnowLevel() {
    this.knowLevels['obj'] = new KnowLevel(config.objDB, 'obj');
    this.knowLevels['basic'] = new KnowLevel(config.rawDB);
    
    _.forEach(config.reducedDB, (value, key) => {
      this.knowLevels[key] = new KnowLevel(value.name);
    });
  }

  filter(query, oid, value) {
    const self = this;
    const filterOptions = filters[oid];
    
    if (filterOptions && filterOptions.collections) {
      const collections = filterOptions.collections;
      _.forEach(collections, (options, counterName) => {
        query[counterName] && self.operate(options, counterName, value);
      });
    }
  }

  operate(options, key, value) {
    if (!(options && options.from && options.from.length > 0)) {
      return;
    }
    let total = 0;
    _.forEach(options.from, (counterName) => {
      total += value[counterName] ? value[counterName] : 0;
    });
    switch(options.operate) {
      case 'sum':
        value[key] = total;
        break;
      case 'avg':
        value[key] = total / options.from.length;
        break;
    }
  }

  getKnowLevel(name) {
    let knowLevel = this.knowLevels[name];
    if (!knowLevel) {
      knowLevel = this.knowLevels['basic'];
    }
    return knowLevel;
  }

  getStartTime(query) {
    let startime = query['start-time'];
    startime = startime ? startime : new Date().getTime() - 100 * 1000;
    return startime;  
  }

  getEndTime(query) {
    let endtime = query['end-time'];
    endtime = endtime ? endtime : new Date().getTime();
    return endtime;
  }

  getQueryOptions(uuid, query) {
    const startime = this.getStartTime(query);
    const endtime = this.getEndTime(query);
    const start = `.rpt.${uuid}.${startime}`;
    const end = `.rpt.${uuid}.${endtime}`;
    return {
      keys: true, 
      values: true,
      gte: start,
      lte: end,
      limit: 100
    };
  }

  report(query) {
    const self = this;
    return new Promise((resolve, reject) => {
      const uuid = query.uuid;
      const oid = query.oid;

      if (!uuid || !oid) {
        reject(); return;
      }
      const db = query.db;
      let knowLevel = this.knowLevels[db];
      if (!knowLevel) {
        knowLevel = this.knowLevels['basic'];  
      }

      const dbOptions = config.reducedDB[db];

      const options = self.getQueryOptions(uuid, query);
      console.log(options);
      knowLevel.find(options, this.filter.bind(this, query)).then((records) => {
        if (dbOptions) {
          self.packageResult(records, self.getStartTime(query), self.getEndTime(query), dbOptions.interval);
        }
        self.mapping.get(oid).then((map) => {
          resolve({keyValue: map, values: records});
        });
      });
    });
  }

  packageResult(result, start, end, duration) {
    console.log(start);
    if (!result || result.length === 0) {
      return [{timestamp: start, data: []}, {timestamp: end, data: []}];
    }

    const zeroPoint = utils.zeroPoint(result[0].data);

    const resultStartTimestamp = result[0].timestamp;
    const resultEndTimestamp = result[result.length - 1].timestamp;
    if (resultStartTimestamp - start > 2 * duration) {
      result.unshift({timestamp: resultStartTimestamp - duration, data: zeroPoint});
      result.unshift({timestamp: start, data: zeroPoint});
    }
    if (resultStartTimestamp - start < 2 * duration && resultStartTimestamp - start > duration) {
      result.unshift({timestamp: start, data: zeroPoint});
    }

    if (end - resultEndTimestamp > 2 * duration) {
      result.push({timestamp: resultEndTimestamp + duration, data: zeroPoint});
      result.push({timestamp: end, data: zeroPoint});
    }

    if (end - resultEndTimestamp <= 2 * duration && end - resultEndTimestamp > duration) {
      result.push({timestamp: end, data: zeroPoint});
    }

  }

  reportObj() {
    return new Promise((resolve, reject) => {
      const knowLevel = this.getKnowLevel('obj');
      knowLevel.find({ values: true }).then(resolve);
    });
  }
}

export default ReportApi;
