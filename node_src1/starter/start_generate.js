
import Faker from './faker';
import KnowLevel from '../src/knowLevel';
import config from '../config';

function multiRecords(knowLevel) {
  const faker = new Faker();
  function load() {
    const oid = 2015;
    const uuid = '13f366fe-1699-11e7-b829-001fa001dd34';
    const key = `.rpt.${uuid}.${new Date().getTime()}.${oid}`;
    console.log(key);
    knowLevel.saveRecord(key, JSON.stringify(faker.record()));
    setTimeout(load, 3000);
  }
  load();
}

const knowLevel = new KnowLevel(config.rawDB);
multiRecords(knowLevel);
