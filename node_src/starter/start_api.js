

import ReportApi from '../src/reportApi';

const reportApi = new ReportApi();
reportApi.find({
  db: 'basic',
  total_connection: true
}, (records) => {
  console.log('Records', records);
});
