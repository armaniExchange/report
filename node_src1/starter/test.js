
import KnowLevel from '../src/knowLevel';

const knowLevel = new KnowLevel('raw_db', 'obj');

knowLevel.find({
  keys: true,
  values: true
}, (records) => {
  console.log(records);
  console.log(records.length);
});
