

import KnowLevel from '../src/KnowLevel';
import ReportClean from '../src/reportClean';
import config from '../config';

const knowLevel = new KnowLevel(config.raw_db);
const reportClean = new ReportClean();

reportClean.start(knowLevel, 2015, '9e29b29e-15de-11e7-81f6-001fa001dd34', 9);

