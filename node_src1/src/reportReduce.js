
import KnowLevel from './knowLevel';
import ReportClean from './reportClean';
import * as utils from './utils';
import config from '../config';
import EventEmitter from 'events';
import _ from 'lodash';

class ReportReduce {

  constructor() {
    // Clean time line
    this.deathLine = 1491554841342;
    this.objects = [];
    this.knowLevels = utils.getKnowLevels(config);
    this.reportClean = new ReportClean();
    this.emitter = new EventEmitter();
    // this.initKnowLevel();
  }
  
  initObject() {
    const self = this;
    return new Promise((resolve, reject) => {
      const knowLevel = self.getKnowLevel('obj');
      const findOptions = { keys: true, values: true };
      knowLevel.find(findOptions).then(resolve);;
    });
  }

  getKnowLevel(name) {
    return this.knowLevels[name];
  }

  getAvailableData(knowLevel, oid, uuid, startime, limit) {
    return new Promise((resolve, reject) => {
      const self = this;
      const start = `.rpt.${uuid}.${startime}`;
      const end = `.rpt.${uuid}.9`
      const options = {
        keys: true,
        values: true,
        gt: start,
        lte: end,
        limit: limit
      }
      knowLevel.find(options).then(resolve);
    });
    
  }

  getLastData(knowLevel, oid, uuid) {
    return new Promise((resolve, reject) => {
      const end = `.rpt.${uuid}.9`;
      const options = {
        keys: true,
        values: true,
        lt: end,
        reverse: true,
        limit: 1
      };
      knowLevel.find(options).then(resolve);
    });
  }

  /**
   * Report data reduce.
   */
  reduce() {
    const self = this;
    self.initObject().then((objects) => {
      const dbs = _.keys(config.reducedDB);
      self.start(objects, dbs, 0);
    });
  }

  /**
   * Start one instance reduce.
   * @param {*Object stats id} oid 
   * @param {*Object instance uuid} uuid 
   */
  start(objects, dbs, dbIndex) {
    const self = this;
    if (dbIndex >= dbs.length) {
      self.destory();
      return;
    }
    // _.forEach(config.reducedDB, (options, key) => {
    const knowLevel = self.getKnowLevel(dbs[dbIndex]);
    const options = config.reducedDB[dbs[dbIndex]];
    
    let objectCount = 0;
    _.forEach(objects, (obj) => {
      const oid = obj.oid;
      const uuid = obj.uuid;
      
      self.getLastData(knowLevel, oid, uuid).then((data) => {
        let startime = 0;
        if (data && data.length > 0) {
          const lastItem = data[0];
          startime = lastItem.timestamp;
        }
        const fromKnowLevel = self.getKnowLevel(options.fromDB);
        const limit = Math.round(options.interval / (_.get(config.reducedDB, [options.fromDB, 'interval']) || 3));
        const reduceOptions = {
          oid: oid,
          uuid: uuid,
          knowLevel: knowLevel,
          fromKnowLevel: fromKnowLevel,
          startime: startime,
          limit: limit,
          interval: options.interval
        };
        self.startReduce(reduceOptions, () => {
          objectCount += 1;
          // Complate all objects reduce for one database.
          if (objectCount === objects.length) {
            self.start(objects, dbs, dbIndex + 1);
          }
        });

      });
    });
  }

  startReduce(options, callback) {
    const self = this;
    self.getAvailableData(options.fromKnowLevel, options.oid, options.uuid, options.startime, options.limit).then((data) => {
      self.checkCollectionData(options, data).then(() => {
        
        // self.saveNewRecord(oid, uuid, toKnowLevel, data).then(() => { 
        //   self.startReduce(options, callback);
        // });
        self.startReduce(options, callback);
      }).catch(callback);
    });
  }

  checkCollectionData(options, data) {
    return new Promise((resolve, reject) => {
      // If data length is limit, add new record.
      // And if startime is 0, add first default record.
      if (!data) {
        reject(); return;
      }
      if (!((data.length == options.limit || (data.length > 0 && options.startime === 0)))) {
        reject(); return;
      }

      const self = this;
      let batch = [];
      let currentime = options.startime;
      let splitIndex = 0;
      _.forEach(data, (item, index) => {
        console.log(item.timestamp);
        if (index === 0 || currentime === 0) {
          currentime = item.timestamp;
        } else if (item.timestamp - currentime > 2 * options.interval) {
          batch.push({
            type: 'put',
            key: utils.keyName(options.oid, options.uuid, item.timestamp),
            value: utils.average(data.slice(splitIndex, index))});

          const zeroData = utils.zeroPoint(item.data);
          // Add one zero point after perious potin.
          batch.push({
            type: 'put',
            key: utils.keyName(options.oid, options.uuid, currentime + options.interval),
            value: zeroData});
          options.startime = currentime + options.interval;
          if (item.timestamp - currentime > 3 * options.interval) {
            // Add one zero point before current point.
            batch.push({
              type: 'put',
              key: utils.keyName(options.oid, options.uuid, item.timestamp - options.interval),
              value: zeroData});
            options.startime = item.timestamp - options.interval;
          }

          currentime = item.timestamp;
          splitIndex = index;
        }
      });

      if (splitIndex === 0) {
        batch.push({  
          type: 'put',
          key: utils.keyName(options.oid, options.uuid, data[data.length - 1].timestamp),
          value: utils.average(data.slice(splitIndex, data.length))});
        options.startime = data[data.length - 1].timestamp;
      }
      console.log(options.startime);
      options.knowLevel.batch(batch).then(resolve);
    });
  }

  saveNewRecord(oid, uuid, knowLevel, recordData) {
    const self = this;
    return new Promise((resolve, reject) => {
      const averageRecord = utils.average(recordData);
      const lastRecord = recordData[recordData.length - 1];
      const key = utils.keyName(oid, uuid, lastRecord.timestamp);
      knowLevel.save(key, JSON.stringify(averageRecord)).then(() => {
        const findOptions = { keys: true, values: true };
        knowLevel.find(findOptions).then((data) => {
          resolve();
        });
      });
    });
  }

  clean() {
    const self = this;
    self.initObject().then((objects) => {
      const dbs = _.keys(config.reducedDB);
      dbs.push('basic');
      self.cleanByObject(objects, dbs, 0);
    });
  }

  cleanByObject(objects, dbs, index) {

    const self = this;
    if (dbIndex >= dbs.length) {
      self.destory();
      return;
    }

    // _.forEach(config.reducedDB, (options, key) => {
    const knowLevelName = dbs[dbIndex];
    const knowLevel = self.getKnowLevel(knowLevelName);
    const duration = knowLevelName === 'basic' 
      ? config.duration 
      : config.reducedDB[knowLevelName].duration;
    
    let objectCount = 0;
    _.forEach(objects, (obj) => {
      const oid = obj.oid;
      const uuid = obj.uuid;
      self.reportClean.start(knowLevel, oid, uuid, duration).then(() => {
        objectCount += 1;
        // Complate all objects reduce for one database.
        if (objectCount === objects.length) {
          self.cleanByObject(objects, dbs, dbIndex + 1);
        }
      });
    });
  }

  destory() {
    const self = this;
    _.forEach(this.knowLevels, (knowLevel) => {
      knowLevel.close();
    });
    self.emitter.emit('over');
  }

  
  on(name, func) {
    this.emitter.on(name, func);
  }

}

export default ReportReduce;



