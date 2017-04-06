
import KnowLevel from '../src/knowLevel';

import config from '../config';
import filters from '../algorithm/filter';
import _ from 'lodash';

class ReportApi {

  constructor() {
    // this.recordKnowLevel = new KnowLevel('record');
    // this.record5KnowLevel = new KnowLevel('record5');
    // this.record10KnowLevel = new KnowLevel('record10');

    this.knowLevels = {};
    this.initKnowLevel();
  }

  initKnowLevel() {
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

  find(query, callback) {
    // if (!query || !query.category) {
    //   callback({err: 'Unknow category!'});
    //   return;
    // }

    

    // const db = '30m';
    const db = query.db;

    // const dbName = _.get(config.reducedDB, [db, 'name']);
    // let knowLevel;

    // if (dbName) {
    //   knowLevel = this.knowLevels[dbName];
    // }
    let knowLevel = this.knowLevels[db];
    if (!knowLevel) {
      knowLevel = this.knowLevels['basic'];  
    }

    let startime = query.startime;
    let endtime = query.endtime;
    startime = startime ? startime : new Date().getTime() - 100 * 1000;
    endtime = endtime ? endtime : new Date().getTime();

    // const start = '.time.2015.13f366fe-1699-11e7-b829-001fa001dd34.1491048879602';
    knowLevel.find({
      keys: true, 
      values: true,
      limit: 100
    }, callback, this.filter.bind(this, query));
  }
}

export default ReportApi;
