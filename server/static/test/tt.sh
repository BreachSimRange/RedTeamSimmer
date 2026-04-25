#!/bin/bash

# ============================================================
# Download CDN Libraries Locally - Fixed Version
# ============================================================

OUTPUT_DIR="${1:-./libs}"

echo "[+] Creating directories..."
mkdir -p "$OUTPUT_DIR/js"
mkdir -p "$OUTPUT_DIR/css"
mkdir -p "$OUTPUT_DIR/fonts"

echo ""
echo "[+] Downloading JavaScript libraries..."

# Lucide Icons
echo "  [1/4] Lucide Icons..."
curl -L -o "$OUTPUT_DIR/js/lucide.min.js" \
    "https://unpkg.com/lucide@0.294.0/dist/umd/lucide.min.js"
echo "        Size: $(wc -c < "$OUTPUT_DIR/js/lucide.min.js") bytes"

# Chart.js
echo "  [2/4] Chart.js..."
curl -L -o "$OUTPUT_DIR/js/chart.min.js" \
    "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
echo "        Size: $(wc -c < "$OUTPUT_DIR/js/chart.min.js") bytes"

# Cytoscape.js
echo "  [3/4] Cytoscape.js..."
curl -L -o "$OUTPUT_DIR/js/cytoscape.min.js" \
    "https://unpkg.com/cytoscape@3.26.0/dist/cytoscape.min.js"
echo "        Size: $(wc -c < "$OUTPUT_DIR/js/cytoscape.min.js") bytes"

# D3.js
echo "  [4/4] D3.js v7..."
curl -L -o "$OUTPUT_DIR/js/d3.v7.min.js" \
    "https://d3js.org/d3.v7.min.js"
echo "        Size: $(wc -c < "$OUTPUT_DIR/js/d3.v7.min.js") bytes"

echo ""
echo "[+] Downloading Bebas Neue font files..."

# Direct font file URLs from Google Fonts
# woff2 format (modern browsers)
echo "  [1/2] Bebas Neue WOFF2..."
curl -L -o "$OUTPUT_DIR/fonts/bebas-neue-latin.woff2" \
    "https://fonts.gstatic.com/s/bebasneue/v14/JTUSjIg69CK48gW7PXoo9Wlhyw.woff2"
echo "        Size: $(wc -c < "$OUTPUT_DIR/fonts/bebas-neue-latin.woff2") bytes"

# woff format (fallback for older browsers)
echo "  [2/2] Bebas Neue WOFF..."
curl -L -o "$OUTPUT_DIR/fonts/bebas-neue-latin.woff" \
    "https://fonts.gstatic.com/s/bebasneue/v14/JTUSjIg69CK48gW7PXoo9Wdhyw.woff"
echo "        Size: $(wc -c < "$OUTPUT_DIR/fonts/bebas-neue-latin.woff") bytes"

echo ""
echo "[+] Creating local CSS for fonts..."

cat > "$OUTPUT_DIR/css/bebas-neue.css" << 'EOF'
/* Bebas Neue - Local */
@font-face {
    font-family: 'Bebas Neue';
    font-style: normal;
    font-weight: 400;
    font-display: swap;
    src: url('../fonts/bebas-neue-latin.woff2') format('woff2'),
         url('../fonts/bebas-neue-latin.woff') format('woff');
}
EOF

echo "        Created: bebas-neue.css"

echo ""
echo "[+] Creating test HTML page..."

cat > "$OUTPUT_DIR/test.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Local Libraries Test</title>
    <link rel="stylesheet" href="css/bebas-neue.css">
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: #0a0a1a;
            color: #eee;
            padding: 2rem;
            margin: 0;
        }
        h1 { font-family: 'Bebas Neue', sans-serif; font-size: 3rem; color: #00d9ff; }
        h2 { font-family: 'Bebas Neue', sans-serif; font-size: 1.8rem; margin-top: 0; }
        .container { max-width: 1000px; margin: 0 auto; }
        .section { 
            background: #12122a; 
            padding: 1.5rem; 
            margin: 1rem 0; 
            border-radius: 8px;
            border-left: 4px solid #00d9ff;
        }
        .status { padding: 0.5rem; margin-top: 1rem; border-radius: 4px; }
        .success { background: #0a2a0a; color: #00ff88; }
        .error { background: #2a0a0a; color: #ff4444; }
        .icons { display: flex; gap: 1.5rem; flex-wrap: wrap; }
        .icons svg { width: 32px; height: 32px; color: #00d9ff; }
        #chart-container { max-width: 500px; height: 300px; }
        #cytoscape-container { width: 100%; height: 300px; background: #080818; border-radius: 4px; }
        #d3-container svg { background: #080818; border-radius: 4px; }
        .font-test { font-family: 'Bebas Neue', sans-serif; font-size: 2rem; color: #ffcc00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Local Libraries Test</h1>
        
        <!-- Font Test -->
        <div class="section">
            <h2>1. Bebas Neue Font</h2>
            <p class="font-test">THIS TEXT SHOULD BE IN BEBAS NEUE FONT</p>
            <p class="font-test">ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789</p>
            <div id="font-status" class="status"></div>
        </div>
        
        <!-- Lucide Icons Test -->
        <div class="section">
            <h2>2. Lucide Icons</h2>
            <div class="icons">
                <i data-lucide="shield"></i>
                <i data-lucide="terminal"></i>
                <i data-lucide="bug"></i>
                <i data-lucide="lock"></i>
                <i data-lucide="wifi"></i>
                <i data-lucide="server"></i>
                <i data-lucide="database"></i>
                <i data-lucide="code"></i>
            </div>
            <div id="lucide-status" class="status"></div>
        </div>
        
        <!-- Chart.js Test -->
        <div class="section">
            <h2>3. Chart.js</h2>
            <div id="chart-container">
                <canvas id="myChart"></canvas>
            </div>
            <div id="chart-status" class="status"></div>
        </div>
        
        <!-- Cytoscape Test -->
        <div class="section">
            <h2>4. Cytoscape.js</h2>
            <div id="cytoscape-container"></div>
            <div id="cytoscape-status" class="status"></div>
        </div>
        
        <!-- D3.js Test -->
        <div class="section">
            <h2>5. D3.js</h2>
            <div id="d3-container"></div>
            <div id="d3-status" class="status"></div>
        </div>
    </div>
    
    <!-- Local Scripts -->
    <script src="js/lucide.min.js"></script>
    <script src="js/chart.min.js"></script>
    <script src="js/cytoscape.min.js"></script>
    <script src="js/d3.v7.min.js"></script>
    
    <script>
        function setStatus(id, success, message) {
            const el = document.getElementById(id);
            el.className = 'status ' + (success ? 'success' : 'error');
            el.innerHTML = (success ? '✓ ' : '✗ ') + message;
        }
        
        // 1. Test Font
        document.fonts.ready.then(() => {
            if (document.fonts.check("1em 'Bebas Neue'")) {
                setStatus('font-status', true, 'Bebas Neue font loaded successfully');
            } else {
                setStatus('font-status', false, 'Bebas Neue font failed to load');
            }
        });
        
        // 2. Test Lucide
        try {
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
                setStatus('lucide-status', true, 'Lucide Icons loaded - version: ' + (lucide.version || 'OK'));
            } else {
                throw new Error('lucide not defined');
            }
        } catch(e) {
            setStatus('lucide-status', false, 'Lucide failed: ' + e.message);
        }
        
        // 3. Test Chart.js
        try {
            if (typeof Chart !== 'undefined') {
                const ctx = document.getElementById('myChart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['T1055', 'T1059', 'T1003', 'T1218', 'T1027'],
                        datasets: [{
                            label: 'Detections',
                            data: [12, 19, 8, 15, 22],
                            backgroundColor: ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff']
                        }]
                    },
                    options: { 
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#eee' } } },
                        scales: { 
                            y: { ticks: { color: '#aaa' }, grid: { color: '#333' } },
                            x: { ticks: { color: '#aaa' }, grid: { color: '#333' } }
                        }
                    }
                });
                setStatus('chart-status', true, 'Chart.js loaded - version: ' + Chart.version);
            } else {
                throw new Error('Chart not defined');
            }
        } catch(e) {
            setStatus('chart-status', false, 'Chart.js failed: ' + e.message);
        }
        
        // 4. Test Cytoscape
        try {
            if (typeof cytoscape !== 'undefined') {
                const cy = cytoscape({
                    container: document.getElementById('cytoscape-container'),
                    elements: [
                        { data: { id: 'attacker', label: 'Attacker' } },
                        { data: { id: 'c2', label: 'C2 Server' } },
                        { data: { id: 'target', label: 'Target' } },
                        { data: { id: 'db', label: 'Database' } },
                        { data: { source: 'attacker', target: 'c2' } },
                        { data: { source: 'c2', target: 'target' } },
                        { data: { source: 'target', target: 'db' } }
                    ],
                    style: [
                        { selector: 'node', style: { 
                            'background-color': '#00d9ff', 
                            'label': 'data(label)',
                            'color': '#fff',
                            'text-valign': 'bottom',
                            'text-margin-y': 8,
                            'font-size': '12px'
                        }},
                        { selector: 'edge', style: { 
                            'width': 2, 
                            'line-color': '#ff6384',
                            'target-arrow-color': '#ff6384',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier'
                        }}
                    ],
                    layout: { name: 'circle', padding: 50 }
                });
                setStatus('cytoscape-status', true, 'Cytoscape.js loaded - version: ' + cytoscape.version);
            } else {
                throw new Error('cytoscape not defined');
            }
        } catch(e) {
            setStatus('cytoscape-status', false, 'Cytoscape failed: ' + e.message);
        }
        
        // 5. Test D3
        try {
            if (typeof d3 !== 'undefined') {
                const data = [30, 86, 168, 234, 125, 190, 98, 150];
                const width = 400, height = 200;
                
                const svg = d3.select('#d3-container')
                    .append('svg')
                    .attr('width', width)
                    .attr('height', height);
                
                const barWidth = width / data.length - 4;
                
                svg.selectAll('rect')
                    .data(data)
                    .enter()
                    .append('rect')
                    .attr('x', (d, i) => i * (barWidth + 4) + 2)
                    .attr('y', d => height - d * 0.8)
                    .attr('width', barWidth)
                    .attr('height', d => d * 0.8)
                    .attr('fill', '#9966ff')
                    .attr('rx', 2);
                    
                setStatus('d3-status', true, 'D3.js loaded - version: ' + d3.version);
            } else {
                throw new Error('d3 not defined');
            }
        } catch(e) {
            setStatus('d3-status', false, 'D3.js failed: ' + e.message);
        }
    </script>
</body>
</html>
EOF

echo "        Created: test.html"

echo ""
echo "============================================"
echo "[+] DOWNLOAD COMPLETE"
echo "============================================"
echo ""
echo "Files downloaded:"
echo ""
ls -lh "$OUTPUT_DIR/js/"
echo ""
ls -lh "$OUTPUT_DIR/fonts/"
echo ""
ls -lh "$OUTPUT_DIR/css/"
echo ""
echo "============================================"
echo "Usage in your HTML:"
echo "============================================"
echo ""
echo '<link rel="stylesheet" href="libs/css/bebas-neue.css">'
echo '<script src="libs/js/lucide.min.js"></script>'
echo '<script src="libs/js/chart.min.js"></script>'
echo '<script src="libs/js/cytoscape.min.js"></script>'
echo '<script src="libs/js/d3.v7.min.js"></script>'
echo ""
echo "Don't forget to initialize Lucide icons:"
echo '<script>lucide.createIcons();</script>'
echo ""
echo "============================================"
echo "Test: Open $OUTPUT_DIR/test.html in browser"
echo "============================================"
