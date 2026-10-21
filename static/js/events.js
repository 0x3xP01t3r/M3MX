/* Named DOM handlers: no inline JavaScript and no dynamic evaluation. */
const m3mxActions = {
  "action-1": function(event) { toggleAlerts(); },
  "action-2": function(event) { toggleTheme(); },
  "action-3": function(event) { clearAlerts(); },
  "action-4": function(event) { navigateTo('home'); },
  "action-5": function(event) { navigateTo('full'); },
  "action-6": function(event) { navigateTo('manual'); },
  "action-7": function(event) { navigateTo('automation'); },
  "action-8": function(event) { navigateTo('extractor'); },
  "action-9": function(event) { navigateTo('ai'); },
  "action-10": function(event) { navigateTo('settings'); },
  "action-11": function(event) { document.getElementById('fileInput').click(); },
  "action-12": function(event) { loadDemo(); },
  "action-13": function(event) { document.getElementById('fileInput').click(); },
  "action-14": function(event) { handleFile(event); },
  "action-15": function(event) { navigateTo('full'); },
  "action-16": function(event) { navigateTo('manual'); },
  "action-17": function(event) { runFullSuite(); },
  "action-18": function(event) { exportReportPdf(); },
  "action-19": function(event) { runAIReport(); },
  "action-20": function(event) { filterPlugins(this.value); },
  "action-21": function(event) { execPlugin(); },
  "action-22": function(event) { extractSelected(); },
  "action-23": function(event) { switchTab(this,'metadata'); },
  "action-24": function(event) { switchTab(this,'hex'); },
  "action-25": function(event) { switchTab(this,'strings'); },
  "action-26": function(event) { switchTab(this,'exif'); },
  "action-27": function(event) { switchTab(this,'image'); },
  "action-28": function(event) { filterStrings(this.value); },
  "action-29": function(event) { filterExif(this.value); },
  "action-30": function(event) { chipSend(this); },
  "action-31": function(event) { chipSend(this); },
  "action-32": function(event) { chipSend(this); },
  "action-33": function(event) { chipSend(this); },
  "action-34": function(event) { cbKey(event); },
  "action-35": function(event) { sendMsg(); },
  "action-36": function(event) { saveSettings(); },
  "action-37": function(event) { this.classList.toggle('on'); },
  "action-38": function(event) { this.classList.toggle('on'); },
  "action-39": function(event) { this.classList.toggle('on'); },
  "action-40": function(event) { this.classList.toggle('on'); },
  "action-41": function(event) { this.classList.toggle('on'); },
  "action-42": function(event) { setTheme(this.value); },
  "action-43": function(event) { toggleParticles(this); },
  "action-44": function(event) { toggleGrain(this); },
  "action-45": function(event) { this.classList.toggle('on'); },
  "expand-finding": function(event) { _faToggleRowDetail(this); }
};
for (const type of ["click", "change", "input", "keydown"]) {
  document.addEventListener(type, function(event) {
    const element = event.target.closest(`[data-${type}]`);
    if (!element || element.disabled) return;
    const action = m3mxActions[element.dataset[type]];
    if (action && action.call(element, event) === false) event.preventDefault();
  });
}
