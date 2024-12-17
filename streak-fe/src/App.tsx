import { useState } from "react";
import z from "zod";

const arr = Array.from({ length: 400 }).map((_, i) => i);

const resSchema = z.array(z.object({ x: z.number(), y: z.number() }));

interface Coords {
	x: number;
	y: number;
}

const BASE_API_URL = "http://localhost:8080";

const calculatePath = async (start: Coords, end: Coords) => {
	const res = await fetch(`${BASE_API_URL}/find-path`, {
		method: "POST",
		body: JSON.stringify({
			start,
			end,
		}),
		headers: {
			"Content-Type": "application/json",
		},
	});
	const data = await res.json();
	return resSchema.parse(data);
};

export default function () {
	const [start, setStart] = useState<Coords | null>(null);
	const [end, setEnd] = useState<Coords | null>(null);
	const [path, setPath] = useState<Coords[]>([]);

	return (
		<div className="min-h-screen w-full space-y-4">
			<div className="flex gap-2">
				{start && end && (
					<button
						type="button"
						onClick={async () => {
							if (!start || !end) return;
							setPath(await calculatePath(start, end));
						}}
						className="border p-1 font-semibold border-black"
					>
						Calculate path
					</button>
				)}
				{(start || end) && (
					<button
						type="button"
						onClick={() => {
							setStart(null);
							setEnd(null);
							setPath([]);
						}}
						className="border p-1 font-semibold border-black"
					>
						Reset
					</button>
				)}
			</div>
			<div
				className="place-content-center gap-2 grid"
				style={{
					gridTemplateColumns: "repeat(20,1fr)",
					gridTemplateRows: "repeat(20,1fr)",
				}}
			>
				{arr.map((item) => {
					const x = item % 20;
					const y = (item - x) / 20;
					const isSelected =
						(start != null && start.x === x && start.y === y) ||
						(end !== null && end.x === x && end.y === y) ||
						!!path.find((item) => item.x === x && item.y === y);
					return (
						<button
							key={item}
							type="button"
							onClick={() => {
								if (!start) {
									setStart({ x, y });
									return;
								}
								if (!end) {
									setEnd({ x, y });
									return;
								}
							}}
							className={`border aspect-square border-black grid place-content-center ${isSelected && `bg-blue-500`}`}
						>
							{x},{y}
						</button>
					);
				})}
			</div>
		</div>
	);
}
