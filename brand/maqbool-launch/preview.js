import { animateMark, markSVG, mountMaqboolLaunch } from './maqbool-launch.js';

const preview = document.querySelector('.preview');
const mark = document.querySelector('#mark');
const themeButton = document.querySelector('#theme');
mark.innerHTML = markSVG;
const svg = mark.querySelector('svg');
svg.setAttribute('aria-hidden', 'true');
let animation;
let launch;

function replay() {
  animation?.cancel();
  animation = animateMark(svg);
}

document.querySelector('#replay').addEventListener('click', replay);
themeButton.addEventListener('click', () => {
  const dark = preview.dataset.theme !== 'dark';
  preview.dataset.theme = dark ? 'dark' : 'light';
  themeButton.textContent = dark ? 'Light background' : 'Dark background';
  themeButton.setAttribute('aria-pressed', String(dark));
});
document.querySelector('#launch').addEventListener('click', () => {
  launch?.destroy();
  mark.hidden = true;
  launch = mountMaqboolLaunch({
    appRoot: preview,
    theme: preview.dataset.theme,
    ready: new Promise((resolve) => setTimeout(resolve, 2850)),
  });
  launch.finished.then(() => { mark.hidden = false; });
});

replay();
