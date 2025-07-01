const table=document.querySelector('table');
const rows=[...table.tBodies[0].rows];
let page=0,perPage=100;
function render(){
  rows.forEach((r,i)=>{r.style.display=(i>=page*perPage&&i<(page+1)*perPage)?'':'none';});
  document.getElementById('page').textContent=`Page ${page+1}`;
}
function next(){if((page+1)*perPage<rows.length){page++;render();}}
function prev(){if(page>0){page--;render();}}
document.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>{
  const idx=[...th.parentNode.children].indexOf(th);
  const asc=th.dataset.asc==='true';
  rows.sort((a,b)=>{const x=a.cells[idx].textContent;const y=b.cells[idx].textContent;return asc?x.localeCompare(y,undefined,{numeric:true}):y.localeCompare(x,undefined,{numeric:true});});
  th.dataset.asc=!asc;
  rows.forEach(r=>table.tBodies[0].appendChild(r));
  render();
}));
function filterTable(){const val=document.getElementById('filter').value.toLowerCase();rows.forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(val)?'':'none';});}
function toggleTheme(){document.body.classList.toggle('dark');localStorage.setItem('theme',document.body.classList.contains('dark')?'dark':'light');}
if(localStorage.getItem('theme')==='dark'){document.body.classList.add('dark');}
const nav=document.createElement('div');
nav.innerHTML='<button id="prev">Prev</button><span id="page"></span><button id="next">Next</button>';
nav.querySelector('#prev').onclick=prev;
nav.querySelector('#next').onclick=next;
document.body.appendChild(nav);
render();
