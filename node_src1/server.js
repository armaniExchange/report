
import express from 'express';

import KnowLevel from './src/knowLevel';
import ReportApi from './src/reportApi';


const app = express();

const reportApi = new ReportApi()

app.get('/report', function(req, res) {
  console.log('Request Params:', req.query);
  reportApi.report(req.query).then((records) => {
    res.send(records);
  });
});

app.get('/obj', function(req, res) {
  console.log('====>');
  reportApi.reportObj().then((records) => {
    res.send(records);
  });
});

app.get('/', function(req, res) {
  res.sendFile(__dirname + '/index.html');
});

app.listen(3000, function() {
  console.log('Example app listening on port 3000');
});
