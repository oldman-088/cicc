import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demoLocales, demoMessages, isDemoLocale, navigationLabels, navigationText, panelLabels, panelText, detailLabels, detailText, syntheticValue, miscLabels, miscText, recordCount } from '../app/demo-locale.ts';

test('demo locales are explicit and translations label partial synthetic status', () => {
  assert.deepEqual(demoLocales, ['en','ar','fa']);
  assert.equal(isDemoLocale(null), false);
  assert.equal(isDemoLocale('invalid'), false);
  for (const locale of demoLocales) {
    assert.equal(isDemoLocale(locale), true);
    const message = demoMessages[locale];
    assert.ok(message.heading && message.subtitle && message.notice && message.partial);
    assert.equal(message.direction, locale === 'en' ? 'ltr' : 'rtl');
  }
});


test('every demo navigation label exists for all supported locales', () => {
  for (const label of Object.keys(navigationLabels) as (keyof typeof navigationLabels)[]) {
    for (const locale of demoLocales) assert.ok(navigationText(label, locale).trim());
  }
});


test('all translated panel labels exist in each locale', () => {
  for (const label of Object.keys(panelLabels) as (keyof typeof panelLabels)[]) {
    for (const locale of demoLocales) assert.ok(panelText(label, locale).trim());
  }
});


test('translated detail labels exist in every locale', () => {
  for (const label of Object.keys(detailLabels) as (keyof typeof detailLabels)[]) {
    for (const locale of demoLocales) assert.ok(detailText(label, locale).trim());
  }
});


test('only known synthetic text is translated; other data is unchanged', () => {
  assert.equal(syntheticValue('Critical','ar',true).text, 'حرج');
  assert.deepEqual(syntheticValue('Critical','ar',false), {text:'Critical',dir:'auto'});
  assert.deepEqual(syntheticValue('unknown value','fa',true), {text:'unknown value',dir:'auto'});
  assert.deepEqual(syntheticValue('Critical','en',true), {text:'Critical',dir:'auto'});
  assert.deepEqual(syntheticValue('constructor','ar',true), {text:'constructor',dir:'auto'});
});


test('remaining translated demo labels and counts exist in each locale', () => {
  for (const label of Object.keys(miscLabels) as (keyof typeof miscLabels)[]) {
    for (const locale of demoLocales) assert.ok(miscText(label, locale).trim());
  }
  for (const locale of demoLocales) assert.ok(recordCount(4, locale).includes('4'));
});
