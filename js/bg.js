(function(){
'use strict';

/* ─── Particles with mouse interaction ─── */
const canvas=document.getElementById('bg-canvas');
if(!canvas) return;
const ctx=canvas.getContext('2d');

let W, H, mouse={x:-9999,y:-9999};
const pts=[];
const COUNT=160;
const CONNECT_DIST=150;

function resize(){W=canvas.width=innerWidth; H=canvas.height=innerHeight;}
resize();
window.addEventListener('resize',resize);

document.addEventListener('mousemove',e=>{mouse.x=e.clientX; mouse.y=e.clientY;});
document.addEventListener('mouseleave',()=>{mouse.x=-9999; mouse.y=-9999;});
document.addEventListener('touchmove',e=>{const t=e.touches[0]; mouse.x=t.clientX; mouse.y=t.clientY;},{passive:true});
document.addEventListener('touchend',()=>{mouse.x=-9999; mouse.y=-9999;});

function Particle(){
  this.x=Math.random()*W;
  this.y=Math.random()*H;
  this.r=Math.random()*2+0.5;
  this.vx=(Math.random()-0.5)*0.6;
  this.vy=(Math.random()-0.5)*0.6;
  this.a=Math.random()*0.4+0.1;
  this.h=260+Math.floor(Math.random()*40); // violet/purple range
}

Particle.prototype.tick=function(){
  // Mouse attraction/repulsion
  const dx=mouse.x-this.x, dy=mouse.y-this.y;
  const dist=Math.sqrt(dx*dx+dy*dy);
  if(dist<200){
    const force=(200-dist)/200*0.3;
    this.vx+=dx/dist*force;
    this.vy+=dy/dist*force;
  }
  // Friction
  this.vx*=0.99;
  this.vy*=0.99;
  // Clamp speed
  const sp=Math.sqrt(this.vx*this.vx+this.vy*this.vy);
  if(sp>1.2){this.vx=this.vx/sp*1.2; this.vy=this.vy/sp*1.2;}

  this.x+=this.vx;
  this.y+=this.vy;
  if(this.x<0) this.x=W;
  if(this.x>W) this.x=0;
  if(this.y<0) this.y=H;
  if(this.y>H) this.y=0;
};

Particle.prototype.draw=function(){
  ctx.beginPath();
  ctx.arc(this.x,this.y,this.r,0,Math.PI*2);
  ctx.fillStyle=`hsla(${this.h},80%,70%,${this.a})`;
  ctx.fill();
};

for(let i=0;i<COUNT;i++) pts.push(new Particle());

/* ─── Shooting stars ─── */
let stars=[];
function spawnStar(){
  const angle=Math.random()*Math.PI*0.4-Math.PI*0.2-Math.PI*0.5;
  const speed=8+Math.random()*6;
  stars.push({
    x:Math.random()*W,
    y:0,
    vx:Math.sin(angle)*speed,
    vy:Math.cos(angle)*speed,
    life:1,
    len:40+Math.random()*60,
  });
}
setInterval(spawnStar,3000+Math.random()*2000);

/* ─── Loop ─── */
function loop(){
  ctx.clearRect(0,0,W,H);

  // Connections
  for(let i=0;i<pts.length;i++){
    for(let j=i+1;j<pts.length;j++){
      const dx=pts[i].x-pts[j].x, dy=pts[i].y-pts[j].y;
      const d=Math.sqrt(dx*dx+dy*dy);
      if(d<CONNECT_DIST){
        ctx.beginPath();
        ctx.moveTo(pts[i].x,pts[i].y);
        ctx.lineTo(pts[j].x,pts[j].y);
        ctx.strokeStyle=`rgba(124,92,252,${0.15*(1-d/CONNECT_DIST)})`;
        ctx.lineWidth=0.6;
        ctx.stroke();
      }
    }
  }

  // Mouse connection glow
  for(let i=0;i<pts.length;i++){
    if(mouse.x<0) break;
    const dx=mouse.x-pts[i].x, dy=mouse.y-pts[i].y;
    const d=Math.sqrt(dx*dx+dy*dy);
    if(d<CONNECT_DIST){
      ctx.beginPath();
      ctx.moveTo(mouse.x,mouse.y);
      ctx.lineTo(pts[i].x,pts[i].y);
      ctx.strokeStyle=`rgba(124,92,252,${0.08*(1-d/CONNECT_DIST)})`;
      ctx.lineWidth=0.5;
      ctx.stroke();
    }
  }

  // Particles
  pts.forEach(p=>{p.tick(); p.draw();});

  // Shooting stars
  for(let i=stars.length-1;i>=0;i--){
    const s=stars[i];
    s.x+=s.vx*0.6;
    s.y+=s.vy*0.6;
    s.life-=0.012;
    if(s.life<=0||s.x<0||s.x>W||s.y>H){stars.splice(i,1); continue;}
    ctx.beginPath();
    ctx.moveTo(s.x-s.vx/s.vy*s.len,s.y-s.len);
    ctx.lineTo(s.x,s.y);
    const grad=ctx.createLinearGradient(s.x,s.y,s.x-s.vx/s.vy*s.len,s.y-s.len);
    grad.addColorStop(0,`rgba(255,255,255,${s.life*0.9})`);
    grad.addColorStop(1,`rgba(255,255,255,0)`);
    ctx.strokeStyle=grad;
    ctx.lineWidth=1.5;
    ctx.stroke();
    // Glow
    ctx.beginPath();
    ctx.arc(s.x,s.y,2.5*s.life,0,Math.PI*2);
    ctx.fillStyle=`rgba(255,255,255,${s.life*0.5})`;
    ctx.fill();
  }

  requestAnimationFrame(loop);
}

loop();

// Spawn first star quickly
setTimeout(spawnStar,500);

})();
