const fs = require('fs');
const d3 = require('d3');
const { JSDOM } = require('jsdom');

const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
const document = dom.window.document;

function createChart(data, filename, title, xFormat = d => d) {
    const width = 800;
    const height = 360;
    const margin = {top: 80, right: 100, bottom: 20, left: 160}; 
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(document.body)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('xmlns', 'http://www.w3.org/2000/svg');

    // Add white background
    svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', '#ffffff');

    const g = svg.append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    // Y scales for groups (dataset size) and inner bars (tools)
    const y0 = d3.scaleBand()
        .domain(data.map(d => d.dataset))
        .rangeRound([0, innerHeight])
        .paddingInner(0.4);

    const y1 = d3.scaleBand()
        .domain(['pyscan', 'pip-audit', 'safety'])
        .rangeRound([0, y0.bandwidth()])
        .padding(0.15);

    const xMax = d3.max(data, d => Math.max(d.pyscan, d['pip-audit'], d.safety));
    const x = d3.scaleLinear()
        .domain([0, xMax])
        .range([0, innerWidth]);

    // Pastel Orange and Classy Grey
    const color = d3.scaleOrdinal()
        .domain(['pyscan', 'pip-audit', 'safety'])
        .range(['#F4A261', '#9CA3AF', '#2A9D8F']); 
        
    const textColor = d3.scaleOrdinal()
        .domain(['pyscan', 'pip-audit', 'safety'])
        .range(['#D97D3A', '#6B7280', '#1C7267']); // Slightly darker for text legibility

    // Title
    svg.append('text')
        .attr('x', margin.left)
        .attr('y', margin.top / 2 - 10)
        .attr('text-anchor', 'start')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '24px')
        .style('font-weight', '600')
        .style('fill', '#111827')
        .text(title);

    // Legend gracefully top-right
    const legend = svg.append('g')
        .attr('transform', `translate(${width - margin.right - 100},${margin.top / 2 - 25})`);
        
    ['Pyscan (Rust)', 'Pip-audit (Python)', 'Safety (Python)'].forEach((label, i) => {
        const key = label.split(' ')[0].toLowerCase();
        const legendRow = legend.append('g')
            .attr('transform', `translate(0, ${i * 26})`);
        
        legendRow.append('rect')
            .attr('width', 14)
            .attr('height', 14)
            .attr('fill', color(key))
            .attr('rx', 4);
            
        legendRow.append('text')
            .attr('x', 24)
            .attr('y', 12)
            .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
            .style('font-size', '14px')
            .style('font-weight', '500')
            .style('fill', '#4B5563')
            .text(label);
    });

    // Dataset Labels (Left side)
    g.append('g')
        .selectAll('text')
        .data(data)
        .join('text')
        .attr('x', -24)
        .attr('y', d => y0(d.dataset) + y0.bandwidth() / 2)
        .attr('dy', '0.32em')
        .attr('text-anchor', 'end')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '15px')
        .style('font-weight', '500')
        .style('fill', '#374151')
        .text(d => d.dataset);

    // Bars
    const group = g.append('g')
      .selectAll('g')
      .data(data)
      .join('g')
        .attr('transform', d => `translate(0,${y0(d.dataset)})`);

    group.selectAll('rect')
      .data(d => ['pyscan', 'pip-audit', 'safety'].map(key => ({key, value: d[key]})))
      .join('rect')
        .attr('x', 0)
        .attr('y', d => y1(d.key))
        .attr('width', d => x(d.value))
        .attr('height', y1.bandwidth())
        .attr('fill', d => color(d.key))
        .attr('rx', 5); // elegant rounded corners

    // Bar Value Labels placed cleanly at the end
    group.selectAll('text')
      .data(d => ['pyscan', 'pip-audit', 'safety'].map(key => ({key, value: d[key]})))
      .join('text')
        .attr('x', d => x(d.value) + 12)
        .attr('y', d => y1(d.key) + y1.bandwidth() / 2)
        .attr('dy', '0.32em')
        .attr('text-anchor', 'start')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '14px')
        .style('font-weight', '600')
        .style('fill', d => textColor(d.key))
        .text(d => xFormat(d.value));

    fs.writeFileSync(filename, svg.node().outerHTML);
    d3.select(document.body).selectAll('*').remove();
}

const timeData = [
    { dataset: 'Small (15 deps)', pyscan: 7.6, 'pip-audit': 3.8, safety: 4.5 },
    { dataset: 'Medium (88 deps)', pyscan: 7.9, 'pip-audit': 41.7, safety: 18.2 },
    { dataset: 'Large (714 deps)', pyscan: 5.7, 'pip-audit': 13.3, safety: 32.1 }
];

const memData = [
    { dataset: 'Small (15 deps)', pyscan: 42, 'pip-audit': 80, safety: 65 },
    { dataset: 'Medium (88 deps)', pyscan: 54, 'pip-audit': 426, safety: 120 },
    { dataset: 'Large (714 deps)', pyscan: 42, 'pip-audit': 117, safety: 210 }
];

createChart(timeData, __dirname + '/execution_time.svg', 'Execution Time', d => d + 's');
createChart(memData, __dirname + '/memory_usage.svg', 'Peak Memory Usage (RSS)', d => d + ' MB');

console.log("SVGs generated.");
