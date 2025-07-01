const table=document.querySelector('table');
const rows=[...table.tBodies[0].rows];
let page=0,perPage=parseInt(localStorage.getItem('perPage')||'100',10);
let sortIdx=null,sortAsc=true;
function render(){
  rows.forEach((r,i)=>{r.style.display=(i>=page*perPage&&i<(page+1)*perPage)?'':'none';});
  document.getElementById('page').textContent=`Page ${page+1}`;
  document.getElementById('rows').value=perPage;
}
function next(){if((page+1)*perPage<rows.length){page++;render();}}
function prev(){if(page>0){page--;render();}}
function sortBy(idx){
  const first=rows[0].cells[idx].textContent;
  const numeric=!isNaN(parseFloat(first));
  const asc=sortIdx===idx? !sortAsc : true;
  rows.sort((a,b)=>{
    const x=a.cells[idx].textContent;
    const y=b.cells[idx].textContent;
    if(numeric){return asc?parseFloat(x)-parseFloat(y):parseFloat(y)-parseFloat(x);} 
    return asc?x.localeCompare(y):y.localeCompare(x);
  });
  sortIdx=idx;sortAsc=asc;
  document.querySelectorAll('th').forEach(th=>th.removeAttribute('aria-sort'));
  const th=table.tHead.rows[0].cells[idx];
  th.setAttribute('aria-sort',asc?'ascending':'descending');
  rows.forEach(r=>table.tBodies[0].appendChild(r));
  render();
}
document.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>{const idx=[...th.parentNode.children].indexOf(th);sortBy(idx);}));
function filterTable(){const val=document.getElementById('filter').value.toLowerCase();rows.forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(val)?'':'none';});}
function toggleTheme(){document.body.classList.toggle('dark');localStorage.setItem('theme',document.body.classList.contains('dark')?'dark':'light');}
if(localStorage.getItem('theme')==='dark'){document.body.classList.add('dark');}
const nav=document.createElement('div');
nav.innerHTML='<button id="prev">Prev</button><span id="page"></span><button id="next">Next</button><select id="rows"><option>50</option><option>100</option><option>200</option></select>';
nav.querySelector('#prev').onclick=prev;
nav.querySelector('#next').onclick=next;
nav.querySelector('#rows').onchange=e=>{perPage=parseInt(e.target.value,10);localStorage.setItem('perPage',perPage);page=0;render();};
document.body.appendChild(nav);
render();
