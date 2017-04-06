
import KnowLevel from './knowLevel';
import SchemaMapping from './SchemaMapping';

import config from '../config';
import filters from '../algorithm/filter';
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

  getQueryOptions(uuid, query) {
    let startime = query.startime;
    let endtime = query.endtime;
    startime = startime ? startime : new Date().getTime() - 100 * 1000;
    endtime = endtime ? endtime : new Date().getTime();
    const start = `.rpt.${uuid}.0`;
    const end = `.rpt.${uuid}.9`;
    return {
      keys: true, 
      values: true,
      start: start,
      end: end,
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

      const options = self.getQueryOptions(uuid, query);
      knowLevel.find(options, (records) => {
        self.mapping.get(oid).then((map) => {
          resolve({keyValue: map, values: records});
        });
      }, this.filter.bind(this, query));

      
    });
  }

  reportObj() {
    return new Promise((resolve, reject) => {
      const knowLevel = this.getKnowLevel('obj');
      knowLevel.find({
        values: true
      }, (records) => {
        console.log(records);
        resolve(records);
      });
    });
  }

}

export default ReportApi;
