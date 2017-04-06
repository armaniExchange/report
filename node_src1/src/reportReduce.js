
import KnowLevel from './knowLevel';
import config from '../config';
import _ from 'lodash';

class ReportReduce {

  constructor() {
    this.fixedValue = 2;
    this.objects = [];
    this.knowLevels = {};
    this.initKnowLevel();
  }

  initKnowLevel() {
    this.knowLevels['obj'] = new KnowLevel(config.objDB, 'obj');
    this.knowLevels['basic'] = new KnowLevel(config.rawDB);
    
    _.forEach(config.reducedDB, (value, key) => {
      this.knowLevels[key] = new KnowLevel(value.name);
    });
  }
  
  initObject(callback) {
    if (!(callback && typeof(callback) === 'function')) {
      return;
    }
    const self = this;
    const knowLevel = self.getKnowLevel('obj');
    knowLevel.find({
      keys: true,
      values: true
    }, (objects) => {
      callback(objects);
    });;
  }

  getKnowLevel(name) {
    return this.knowLevels[name];
  }

  getKey(oid, uuid, timestamp) {
    return `.rpt.${uuid}.${timestamp}.${oid}`;
  }

  // getFirstData(knowLevel, oid, uuid, callback) {
  //   const start = `.time.${oid}.${uuid}.0`;
  //   const options = {
  //     keys: true,
  //     values: true,
  //     start: start,
  //     limit: 1
  //   }

  //   knowLevel.find(options, callback);
  // }

  getAvailableData(knowLevel, oid, uuid, startime, limit, callback) {
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

    knowLevel.find(options, callback);
  }

  getInitialData(knowLevel, oid, uuid, startime, limit, callback) {
    const self = this;
    const start = `.rpt.${uuid}.${startime}`;
    const options = {
      keys: true,
      values: true,
      lt: start
    }

    knowLevel.find(options, callback);
  }

  deleteBatchByKeys(knowLevel, keys) {
    let batchs = [];
    _.forEach(keys, (key) => {
      batchs.push({type: 'del', key: key});
    });
    console.log(batchs);
  }

  getLastData(knowLevel, oid, uuid, callback) {
    const end = `.rpt.${uuid}.9`;
    const options = {
      keys: true,
      values: true,
      lt: end,
      reverse: true,
      limit: 1
    };

    knowLevel.find(options, callback);
  }

  reduce() {
    const self = this;
    self.initObject((objects) => {
      _.forEach(objects, (obj) => {
        console.log(obj.oid, obj.uuid);
        self.start(obj.oid, obj.uuid);
      });
    });

    
  }

  start(oid, uuid) {
    const self = this;
    _.forEach(config.reducedDB, (options, key) => {
      const knowLevel = self.getKnowLevel(key);
      self.getLastData(knowLevel, oid, uuid, (data) => {
        let startime = 0;
        if (data && data.length > 0) {
          const lastItem = data[0];
          startime = lastItem.timestamp;
        }
        const fromKnowLevel = self.getKnowLevel(options.fromDB);
        const limit = Math.round(options.duration / (_.get(config.reducedDB, [options.fromDB, 'duration']) || 3));
        self.startReduce(fromKnowLevel, knowLevel, oid, uuid, startime, limit);
      });
    });
  }

  startReduce(fromKnowLevel, toKnowLevel, oid, uuid, startime, limit) {
    const self = this;
    self.getAvailableData(fromKnowLevel, oid, uuid, startime, limit, (data) => {
      // If data length is limit, add new record.
      // And if startime is 0, add first default record.
      // console.log(data);
      if (data && (data.length === limit || (data.length > 0 && startime === 0))) {
        const lastRecordTime = data[data.length - 1].timestamp;
        self.saveNewRecord(oid, uuid, toKnowLevel, data, () => {
          // const newStartime = data[dataLength - 1].timestamp;
          self.startReduce(fromKnowLevel, toKnowLevel, oid, uuid, lastRecordTime, limit);
        });
      } else {
        // Haven't point.
      }
    });
  }

  saveNewRecord(oid, uuid, knowLevel, recordData, callback) {
    const self = this;
    const averageRecord = self.average(recordData);
    const lastRecord = recordData[recordData.length - 1];
    const key = self.getKey(oid, uuid, lastRecord.timestamp);
    console.log(key);
    knowLevel.saveRecord(key, JSON.stringify(averageRecord), () => {
      knowLevel.find({
        keys: true,
        values: true
      }, function(data) {
        console.log(`Total ${knowLevel.name} Length:`, data.length);
        callback();
      });
    });
  }

  average(data) {
    let total = {};
    data.map((item) => {
      _.forEach(item.data, (value, key) => {
        total[key] = total[key] ? total[key] : 0; 
        total[key] += value;
      });
    });
    
    let result = {};
    let length = data.length;
    _.forEach(total, (value, key) => {
      result[key] = Math.round(total[key] / length);
    });
    return result;
  }

}

export default ReportReduce;


