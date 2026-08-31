import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { useReducedMotion } from '../../hooks/useReducedMotion';
import { CanvasFallback } from './CanvasFallback';

interface SecurityCoreSceneProps {
  threatMode?: boolean;
}

export const SecurityCoreScene: React.FC<SecurityCoreSceneProps> = ({ threatMode = false }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hasWebGL, setHasWebGL] = useState<boolean>(true);
  const prefersReducedMotion = useReducedMotion();

  useEffect(() => {
    if (prefersReducedMotion || !containerRef.current) {
      return;
    }

    const container = containerRef.current;
    let animId: number;
    let renderer: THREE.WebGLRenderer;
    let scene: THREE.Scene;
    let camera: THREE.PerspectiveCamera;

    // Check WebGL availability safely
    try {
      const testCanvas = document.createElement('canvas');
      const gl = testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
      if (!gl) {
        setHasWebGL(false);
        return;
      }
    } catch {
      setHasWebGL(false);
      return;
    }

    try {
      const width = container.clientWidth || 450;
      const height = container.clientHeight || 450;

      scene = new THREE.Scene();
      camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 100);
      camera.position.z = 4.8;

      renderer = new THREE.WebGLRenderer({
        alpha: true,
        antialias: true,
        powerPreference: 'high-performance',
      });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      container.appendChild(renderer.domElement);

      const mainGroup = new THREE.Group();

      // Primary Cyber Theme Colors
      const cyanColor = threatMode ? 0xf43f5e : 0x22d3ee;
      const emeraldColor = threatMode ? 0xfb923c : 0x34d399;

      // 1. Outer Wireframe Icosahedron
      const outerGeo = new THREE.IcosahedronGeometry(1.7, 1);
      const outerMat = new THREE.MeshBasicMaterial({
        color: cyanColor,
        wireframe: true,
        transparent: true,
        opacity: 0.35,
      });
      const outerMesh = new THREE.Mesh(outerGeo, outerMat);
      mainGroup.add(outerMesh);

      // 2. Inner Wireframe Shield
      const innerGeo = new THREE.IcosahedronGeometry(1.3, 1);
      const innerMat = new THREE.MeshBasicMaterial({
        color: emeraldColor,
        wireframe: true,
        transparent: true,
        opacity: 0.25,
      });
      const innerMesh = new THREE.Mesh(innerGeo, innerMat);
      mainGroup.add(innerMesh);

      // 3. Central Energy Core Sphere
      const coreGeo = new THREE.IcosahedronGeometry(0.55, 2);
      const coreMat = new THREE.MeshBasicMaterial({
        color: cyanColor,
        transparent: true,
        opacity: 0.08,
      });
      const coreMesh = new THREE.Mesh(coreGeo, coreMat);
      mainGroup.add(coreMesh);

      // 4. Rotating Radar Sweep Plane
      const sweepPivot = new THREE.Group();
      const sweepGeo = new THREE.CircleGeometry(2.1, 32, 0, Math.PI / 3.5);
      const sweepMat = new THREE.MeshBasicMaterial({
        color: cyanColor,
        transparent: true,
        opacity: 0.08,
        side: THREE.DoubleSide,
      });
      const sweepMesh = new THREE.Mesh(sweepGeo, sweepMat);
      sweepMesh.rotation.x = -Math.PI / 2;
      sweepPivot.add(sweepMesh);
      mainGroup.add(sweepPivot);

      // 5. Floating Threat/Security Particle Cloud
      const particleCount = 140;
      const particlePositions = new Float32Array(particleCount * 3);
      const particleVelocities: number[] = [];

      for (let i = 0; i < particleCount; i++) {
        const r = 1.7 + Math.random() * 1.8;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        particlePositions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
        particlePositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
        particlePositions[i * 3 + 2] = r * Math.cos(phi);
        particleVelocities.push((Math.random() - 0.5) * 0.004);
      }

      const particleGeo = new THREE.BufferGeometry();
      particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
      const particleMat = new THREE.PointsMaterial({
        color: emeraldColor,
        size: 0.045,
        transparent: true,
        opacity: 0.65,
        sizeAttenuation: true,
      });
      const particleCloud = new THREE.Points(particleGeo, particleMat);
      mainGroup.add(particleCloud);

      scene.add(mainGroup);

      // Mouse Parallax Trackers
      let mouseX = 0;
      let mouseY = 0;
      let targetRotX = 0;
      let targetRotY = 0;

      const handleMouseMove = (e: MouseEvent) => {
        mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
        mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
      };

      window.addEventListener('mousemove', handleMouseMove, { passive: true });

      // Animation Loop
      const clock = new THREE.Clock();
      const animate = () => {
        animId = requestAnimationFrame(animate);
        const elapsedTime = clock.getElapsedTime();

        // Rotations
        outerMesh.rotation.y += 0.003;
        outerMesh.rotation.x += 0.001;
        innerMesh.rotation.y -= 0.0025;
        innerMesh.rotation.z += 0.001;
        sweepPivot.rotation.y += 0.015;
        particleCloud.rotation.y += 0.001;

        // Core Pulse
        const pulse = 1 + Math.sin(elapsedTime * 2) * 0.08;
        coreMesh.scale.set(pulse, pulse, pulse);
        coreMat.opacity = 0.06 + Math.sin(elapsedTime * 2.5) * 0.03;

        // Parallax Interpolation
        targetRotY = mouseX * 0.3;
        targetRotX = -mouseY * 0.2;
        mainGroup.rotation.y += (targetRotY - mainGroup.rotation.y) * 0.05;
        mainGroup.rotation.x += (targetRotX - mainGroup.rotation.x) * 0.05;

        // Particle Drift
        const positions = particleGeo.attributes.position.array as Float32Array;
        for (let i = 0; i < particleCount; i++) {
          positions[i * 3 + 1] += particleVelocities[i];
          if (positions[i * 3 + 1] > 3.5 || positions[i * 3 + 1] < -3.5) {
            particleVelocities[i] *= -1;
          }
        }
        particleGeo.attributes.position.needsUpdate = true;

        renderer.render(scene, camera);
      };

      animate();

      // Resize Listener
      const handleResize = () => {
        if (!container) return;
        const newW = container.clientWidth;
        const newH = container.clientHeight;
        if (newW > 0 && newH > 0) {
          camera.aspect = newW / newH;
          camera.updateProjectionMatrix();
          renderer.setSize(newW, newH);
        }
      };

      window.addEventListener('resize', handleResize);

      // Cleanup
      return () => {
        cancelAnimationFrame(animId);
        window.removeEventListener('mousemove', handleMouseMove);
        window.removeEventListener('resize', handleResize);

        if (renderer.domElement && container.contains(renderer.domElement)) {
          container.removeChild(renderer.domElement);
        }

        renderer.dispose();
        outerGeo.dispose();
        outerMat.dispose();
        innerGeo.dispose();
        innerMat.dispose();
        coreGeo.dispose();
        coreMat.dispose();
        sweepGeo.dispose();
        sweepMat.dispose();
        particleGeo.dispose();
        particleMat.dispose();
      };
    } catch (err) {
      console.warn('Three.js initialization fallback:', err);
      setHasWebGL(false);
    }
  }, [prefersReducedMotion, threatMode]);

  if (prefersReducedMotion || !hasWebGL) {
    return <CanvasFallback threatMode={threatMode} />;
  }

  return (
    <div className="relative w-full aspect-square max-w-[500px] mx-auto flex items-center justify-center">
      {/* Ambient Radial Glow Backdrops */}
      <div className={`absolute w-[80%] h-[80%] rounded-full blur-3xl opacity-20 pointer-events-none ${
        threatMode ? 'bg-danger' : 'bg-cyan'
      }`} />
      
      {/* Three.js DOM Canvas Container */}
      <div ref={containerRef} className="w-full h-full relative z-10" />
    </div>
  );
};
