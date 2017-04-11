
import Faker from './faker';
import KnowLevel from '../src/knowLevel';
import config from '../config';
import * as utils from '../src/utils';

function multiRecords(knowLevel) {
  const faker = new Faker();
  function load() {
    const oid = 2015;
    const uuid = '9e29b29e-15de-11e7-81f6-001fa001dd34';
    const key = `.rpt.${uuid}.${utils.getCurrentTimestamp()}.${oid}`;
    knowLevel.save(key, JSON.stringify(faker.record())).then(() => {
      console.log('Save successfull', key);
    });
    setTimeout(load, 3000);
  }
  load();
}

const knowLevel = new KnowLevel(config.rawDB);
multiRecords(knowLevel);

// const knowLevel = new KnowLevel(config.objDB, 'object');

// knowLevel.find({}).then((records) => {
//   console.log(records);
// });;
