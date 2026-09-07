const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../deploy/web/static/app.js'), 'utf8');
function productionFunction(name) {
  const start = source.indexOf(`  function ${name}(`) >= 0
    ? source.indexOf(`  function ${name}(`) : source.indexOf(`  async function ${name}(`);
  assert.ok(start >= 0, `Missing production function ${name}`);
  const rest = source.slice(start);
  const end = rest.slice(1).search(/\n  (?:async )?function /);
  return end < 0 ? rest : rest.slice(0, end + 1);
}
function element(tag, className, text) {
  return { tag, className, textContent: text, children: [], dataset: {}, attributes: {},
    append(...items) { this.children.push(...items); },
    setAttribute(key, value) { this.attributes[key] = value; },
    get childElementCount() { return this.children.length; } };
}
(async () => {
  const group = { name: 'Residential-US-All', runtimeSelected: 'node A', runtimeCandidates: ['node A', 'node B'] };
  const target = element('div');
  const state = { groups: [group], groupDiagnostics: new Map(), groupDiagnosticsTesting: '', activeTab: 'groups',
    groupPicker: { kind: 'runtime', groupName: group.name, sections: [{title: 'Nodes', items: [
      {value: 'node A', label: 'node A'}, {value: 'node B', label: 'node B'}]}] } };
  const requests = [], opened = [];
  const context = vm.createContext({ state, node: element,
    $: selector => selector === '#group-picker-options' ? target : { value: '' },
    empty: item => { item.children = []; }, renderGroups() {}, toast() {}, errorMessage: String,
    identifierPath: encodeURIComponent,
    chooseRuntimeNode: async item => opened.push(item.name),
    api: async (url, options) => { requests.push({url, options}); return {data: {items: [
      {member:'node A', status:'ok', delayMs:359}, {member:'node B', status:'timeout'}]}}; }
  });
  vm.runInContext(productionFunction('renderGroupPickerOptions') + '\n' + productionFunction('testGroupNodes'), context);
  await context.testGroupNodes(group);
  assert.equal(requests.length, 1);
  assert.ok(requests[0].url.endsWith('/delays'));
  assert.equal(state.groups[0].runtimeSelected, 'node A');
  assert.deepEqual(opened, [group.name]);
  assert.equal(state.groupDiagnosticsTesting, '');
  context.renderGroupPickerOptions();
  const buttons = target.children.filter(item => item.tag === 'button');
  assert.equal(buttons.length, 2);
  assert.equal(buttons[0].disabled, true);
  assert.equal(buttons[0].children.at(-1).textContent, '当前选择');
  assert.equal(buttons[0].children[1].textContent, '359 ms');
  assert.equal(buttons[1].disabled, false);
  assert.equal(buttons[1].children.at(-1).textContent, '选择此节点');
  assert.equal(buttons[1].children[1].textContent, '超时');
  context.openGroupPicker = async () => 'node B';
  context.loadGroups = async () => {};
  vm.runInContext(productionFunction('chooseRuntimeNode'), context);
  await context.chooseRuntimeNode(group);
  assert.equal(requests.length, 2);
  assert.ok(requests[1].url.endsWith('/runtime'));
  assert.equal(requests[1].options.method, 'PUT');
  assert.equal(requests[1].options.body.member, 'node B');
  console.log('[OK] Provider node picker, delay results and explicit selection');
})().catch(error => { console.error(error); process.exitCode = 1; });
